#!/bin/sh
# PIM-SM regression lab for FreeBSD, using vnet jails
#
# Exercises the FreeBSD-specific code paths of pimd that no CI covers: the
# rest of this directory is Linux-only, it is built on network namespaces,
# veth pairs and `unshare`, so on FreeBSD none of it can even start, and it
# is not in TESTS for that reason.  Everything asserted here goes through
# routesock.c (RPF lookups over the PF_ROUTE socket) and the kern.c BSD
# branches, rather than netlink.c and the Linux ones.
#
# What makes this possible on FreeBSD:
#   - sys/netinet/ip_mroute.c is fully VNET-ized (V_viftable, V_numvifs,
#     V_ip_mrouter, V_multicast_register_if), so each vnet jail owns a
#     private multicast forwarding cache and vif table.
#   - prison_priv_check() grants PRIV_NETINET_MROUTE, PRIV_NETINET_RAW and
#     PRIV_NET_BPF unconditionally to jails with their own network stack
#     (sys/kern/kern_jail.c), so pimd's raw IGMP/PIM sockets and its
#     MRT_INIT setsockopt() work inside a jail with no allow.raw_sockets.
#   - ip_mroute.ko has to be loaded from the host: a jail cannot kldload.
#
# Topology, one vnet jail per box, all links /24:
#
#    ED1            R1             R2             R3            ED2
#  (sender)     (FHR / DR)     (BSR + RP)        (LHR)       (receiver)
#     |              |              |              |              |
#     +--10.0.1.0/24-+-10.0.12.0/24-+-10.0.23.0/24-+--10.0.3.0/24-+
#      .10        .1   .1        .2   .2        .3   .1        .10
#     epair101a/b     epair112a/b    epair123a/b    epair203a/b
#
# Unicast routing is static on purpose: pimd cannot read distance/metric
# from the kernel anyway (it uses the values from pimd.conf), so adding
# bird or frr here would only add a dependency and a second thing to
# debug.  The RP is pinned to R1's side of the R1-R2 link (10.0.12.2) so
# the expected RP address is deterministic instead of "highest active IP".
#
# Multicast then has to survive the full PIM-SM sequence: ED2's IGMP
# report reaches R3, R3 sends a (*,G) join toward the RP, ED1's first
# packet makes R1 PIM-register-encapsulate to R2, R2 decapsulates and
# forwards down the shared tree, and with spt-threshold set low the
# routers then switch to the shortest path tree.
#
# Seven scenarios share that topology.  The first three differ only in which
# pimd.conf each router gets and which assertions run; the two gif ones also
# add a tunnel and take R2 out of PIM entirely; the last one rebuilds the
# two right hand links as bridged segments and hangs a fourth router off
# them:
#
#   rpt         R2 is BSR and RP, ED2 joins, traffic has to reach it over
#               the shared tree.  Takes about 90s.
#   keepalive   R1 is BSR and RP for its own directly connected source and
#               nobody joins the group, which is the setup of
#               https://github.com/troglobit/pimd/issues/251.  The (S,G)
#               entries then have an empty outgoing interface list, and
#               pimd used to restart the entry timer only for entries that
#               had outgoing interfaces: every source was aged out a few
#               seconds after a cache miss had recreated it, so sources
#               kept appearing and disappearing while they were sending.
#               Takes about 5 minutes, it has to outlive PIM_DATA_TIMEOUT
#               (210s).
#   rp-lasthop  R3 is BSR and RP *and* the last hop router for the only
#               receiver, while the source sits behind R1 two hops away,
#               which is the setup of
#               https://github.com/troglobit/pimd/issues/243.  Everybody
#               there reports the same thing over a tunnel: traffic from a
#               source remote to the RP never reaches the receivers that
#               hang off the RP itself, and moving the RP to the other end
#               moves the broken direction with it.  Takes about 2 minutes.
#
#               No other test covers this shape: rp.sh keeps the two roles
#               on separate routers (R2 is RP, R3 is last hop), so the RP
#               there never has a directly connected member and its (*,G)
#               never has the register vif as its incoming interface.
#   gif-tunnel  rp-lasthop again, but R1 and R3 are joined by a gif tunnel
#               across a plain unicast R2 that runs no pimd at all, which
#               is the shape everyone on #243 actually runs: two PIM
#               routers either side of a VPN, nothing but IP in between.
#
#                 ED1 --- R1 ==== gif0, 172.16.0.0/24 ==== R3 --- ED2
#                          \                              /
#                           +--- R2, unicast only -------+
#
#               What this adds over rp-lasthop is the interface type.  A
#               gif is IFF_POINTOPOINT, so config_vifs_from_kernel() takes
#               the peer from ifa_dstaddr and sets VIFF_POINT_TO_POINT and
#               VIFF_REXMIT_PRUNES (src/config.c), a path no epair in this
#               lab ever reaches.  The inner addresses deliberately carry a
#               /24 rather than a /30 or a bare peer address, because that
#               is what the WireGuard and OpenVPN configs in the issue use:
#               a point-to-point link whose netmask claims a whole subnet.
#               Takes about 2 minutes.
#   gif-tunnel-staticrp
#               gif-tunnel again, but the RP is configured with a static
#               "rp-address" on both ends instead of being elected, which is
#               how every pimd.conf quoted in #243 is written.  That is a
#               different code path, not another way of reaching the same
#               state: my_cand_rp_address is only ever assigned while
#               parsing cand_rp (src/config.c), so with a static RP it stays
#               0.0.0.0 and the router that *is* the RP answers "no" to
#               every internal test of whether it is.  Takes about 3
#               minutes.
#   shared-lan  The only scenario with more than one PIM router on a link.
#               Three PIM routers share one segment, so PIM has to run the
#               elections that a point-to-point link never needs:
#
#                                          .--- R3 ---.
#                                         /            \
#     ED1 --- R1 --- R2 --- br0 ---------+            br1 --+--- R5 --- ED2
#           (FHR)  (BSR/RP)               \            /    |
#                                          '--- R4 ---'     '--- ED3
#
#         10.0.1/24   10.0.12/24   10.0.23/24      10.0.3/24    10.0.5/24
#
#               R3 (10.0.3.2), R4 (10.0.3.3) and R5 (10.0.3.1) all sit on
#               br1, and the addresses put its two elections on different
#               routers: R4 is the PIM DR, because DR election falls back to
#               the highest address (restart_dr_election() in
#               src/pim_proto.c), while R5 is the IGMP querier, because that
#               election takes the lowest one (src/igmp_proto.c).
#
#               An assert needs two routers putting the same stream on one
#               LAN, and here they get there by different routes.  R4
#               forwards because ED3's IGMP report is its leaf: the report
#               reaches every router on the segment, but add_leaf()
#               (src/route.c) looks the group up with DONT_CREATE unless the
#               receiving vif is the DR's, so only the DR ever acts on it.
#               IGMP can therefore hand an oif to R4 and to nobody else, and
#               the second forwarder has to come from PIM: R5 wants the group
#               for ED2 and its RPF neighbour is R3, so its Join names R3 as
#               the upstream router, and receive_pim_join_prune()
#               (src/pim_proto.c) only lets the router named in a Join add
#               the oif - the rest of the LAN uses it for suppression.
#
#               R3 and R4 then both forward onto br1, each sees the other's
#               copy arrive on an interface that is not its iif, the kernel
#               raises IGMPMSG_WRONGVIF for it (ip_mroute.c, with the assert
#               upcalls pimd turns on through MRT_PIM), and the assert that
#               follows moves the loser's oif into asserted_oifs (calc_oifs()
#               in src/route.c).  None of that is reachable in any other
#               scenario here: every other link is an epair with exactly one
#               router at each end.  Takes about 3 minutes.
#   shared-lan-spt
#               The same LAN and the same two contenders, but R5 is allowed
#               onto the shortest path tree, so R3 ends up with (S,G)
#               forwarding state of its own while R4 still has nothing but
#               ED3's (*,G) leaf.
#
#               That is supposed to decide the assert on its own.  RFC 7761
#               4.6.1 compares assert metrics field by field with
#               rpt_bit_flag first, and my_assert_metric() (p.93) returns
#               the SPT metric, with that flag clear, only when
#               CouldAssert(S,G,I) holds - which requires SPTbit(S,G) ==
#               TRUE (p.75).  R4 has no (S,G) state, so it must assert with
#               the flag set and lose to R3 before either address is looked
#               at.  R3 has the *lower* address, so a router that gets this
#               right and one that falls through to the tiebreak give
#               opposite answers, and the scenario can tell them apart.
#
#               pimd gets it wrong today, and the scenario says so rather
#               than skipping the case: assertion 9 reports KNOWN instead
#               of FAIL, and turns into an ok the day the RPT bit is set
#               correctly.  send_pim_assert() (src/pim_proto.c) takes the
#               bit straight from MRTF_RP on the entry it is forwarding
#               off, and MRTF_RP is only ever set from an explicit
#               (S,G,rpt) Join/Prune or when an entry's iif changes to
#               point at the RP (src/route.c, src/mrt.c) - never on the
#               (S,G) that a cache miss builds underneath a (*,G).  So R4
#               claims the shortest path tree it never joined, the metrics
#               tie, and the address hands it a win the spec does not.
#               Takes about 3 minutes.
#   ssm         IGMPv3 (S,G) membership state on R3, the last hop router,
#               for a group in the 232.0.0.0/8 SSM range.  The only
#               scenario about what IGMP leaves behind on a router rather
#               than about what PIM forwards, and the only one where a
#               group has a source list at all: everywhere else the
#               receiver joins (*,G) and pimd keeps no sources for it.
#
#               ED2 reports two sources, blocks one, and then goes quiet.
#               The membership that is left has to expire on its own, and
#               it used to be unable to: a group held one membership timer,
#               carrying whichever source had reported last, so blocking
#               that source cancelled the only timer the group had while
#               leaving its other source in place.  Nothing then aged the
#               group out, on any timescale.  A leave for the last source
#               still cleaned up, which is why this needs a receiver that
#               stops reporting rather than one that leaves, and why no
#               scenario built on mping could show it: a kernel that joined
#               a group answers every query afterwards, and a receiver
#               taken off the LAN takes the epair, and R3's vif, with it.
#               The reports come from test/igmpv3.c for that reason - one
#               report, sent exactly as asked, and nothing after it.
#               Takes about 90s.
#
# The scenarios cannot run in parallel: they use the same jail names and
# epairs, and net.inet.ip.mcast.loop is a host-global sysctl.
#
# Usage:
#   ./freebsd-lab.sh start [scenario]   build the lab, start pimd on its routers
#   ./freebsd-lab.sh check [scenario]   run the assertions (start must have run)
#   ./freebsd-lab.sh run   [scenario]   start + check + stop, exit 0 if all pass
#   ./freebsd-lab.sh stop               tear everything down
#
# where scenario is "rpt" (default), "keepalive", "rp-lasthop",
# "gif-tunnel", "gif-tunnel-staticrp", "shared-lan", "shared-lan-spt", or
# "all" for run.
#
# Requires: root (via sudo), VIMAGE kernel, ip_mroute.ko, if_bridge.ko for
# shared-lan, and a built pimd tree in $PIMD_SRC (./autogen.sh &&
# ./configure && gmake).

set -eu

SUDO=${SUDO:-sudo}
# The tree this script lives in, so it tests the pimd next to it rather
# than whatever is installed.  Override to point somewhere else.
PIMD_SRC=${PIMD_SRC:-$(cd "$(dirname "$0")/.." && pwd)}
WORKDIR=${WORKDIR:-/tmp/pimd-test}
GROUP=${GROUP:-225.1.2.3}
GROUP_DEFAULT=$GROUP
SCENARIO=${SCENARIO:-rpt}

# keepalive: groups the source blasts at, and how long the entries must
# survive.  KEEP_SECONDS has to exceed PIM_DATA_TIMEOUT in src/pimd.h.
KEEP_GROUP=${KEEP_GROUP:-239.1.1.5}
KEEP_NUM=${KEEP_NUM:-3}
KEEP_SECONDS=${KEEP_SECONDS:-240}

# pimd debug flags, e.g. DEBUG="-l debug -d mrt,rpf" or "-l debug -d all"
DEBUG=${DEBUG:-"-l debug -d mrt,rpf,pim_register,pim_bootstrap"}

PIMD="$PIMD_SRC/src/pimd"
PIMCTL="$PIMD_SRC/src/pimctl"
MPING="$WORKDIR/mping"
IGMPV3="$WORKDIR/igmpv3"
# mping joins the group it sends to, which would give the (S,G) entries a
# leaf and hide the bug the keepalive scenario is after.  That scenario
# needs a source that only sends, so it gets its own little sender.
MSEND="$WORKDIR/msend"

BOXES="ed1 r1 r2 r3 ed2"
ROUTERS="r1 r2 r3"
EPAIRS="epair101 epair112 epair123 epair203"
ED2_IF=epair203b

# shared-lan: the two right hand links become bridged segments, carrying two
# more routers and a second end device.  Only the "b" end of a bridged epair
# goes into a jail, its "a" end stays on the host as a bridge member, so
# create_lans() has to create those before the jails: create_box() creates
# the pairs whose "a" end the box itself owns, and it owns none of them.
# epair510, the ordinary point-to-point link from R5 down to ED2, is left to
# create_box() like every link in the other scenarios.
SHARED_BOXES="ed1 r1 r2 r3 r4 r5 ed2 ed3"
SHARED_ROUTERS="r1 r2 r3 r4 r5"
BR_UPSTREAM=bridge223
BR_RECEIVER=bridge303
BR_UPSTREAM_EPAIRS="epair223 epair323 epair423"
BR_RECEIVER_EPAIRS="epair503 epair303 epair403 epair603"
SHARED_EPAIRS="$BR_UPSTREAM_EPAIRS $BR_RECEIVER_EPAIRS epair510"

# Everything any scenario can create, so stop() cleans up without having to
# be told which one was running.
ALL_BOXES="ed1 r1 r2 r3 r4 r5 ed2 ed3"
ALL_EPAIRS="$EPAIRS $SHARED_EPAIRS"

# Source and RP addresses the assertions expect
SRC_ADDR=10.0.1.10
RP_ADDR=10.0.12.2

# rp-lasthop: the RP moves to R3, on the interface facing the receiver, so
# the router that is RP is also the one with the directly connected member.
RCV_ADDR=10.0.3.10
RPLH_ADDR=10.0.3.1

# shared-lan: the shared segment is 10.0.3.0/24, with three PIM routers and
# one end device on it.  The addresses are what decide the two elections
# held there, and they are picked so the elections land on different
# routers: PIM takes the highest address, so R4 is the DR, IGMP takes the
# lowest, so R5 is the querier.
#
# R5 must not be the DR, hence its address at the bottom of the range.  Its
# RPF interface for the group is the shared LAN itself, so an oif there
# would be its own incoming interface and calc_oifs() would drop it: were R5
# the DR, ED3's membership would give nobody a usable oif and the scenario
# would have one forwarder instead of two.
SL_R3_IF=epair303b
SL_R4_IF=epair403b
SL_R3_ADDR=10.0.3.2
SL_DR_ADDR=10.0.3.3
SL_QUERIER_ADDR=10.0.3.1
SL_ED3_ADDR=10.0.3.10

# ED3 joins the group on a port of its own.  IGMP membership is per group,
# not per port, so R4 sees a report and takes the leaf, while the stream
# ED1 sends to $GROUP:4321 never reaches ED3's socket and it answers none of
# it.  That keeps every reply the sender counts a reply from ED2, at the far
# end of the tree, rather than one from a member sitting on the LAN itself.
SL_JOIN_PORT=${SL_JOIN_PORT:-4322}

# Replies the sender must get back before the stream counts as forwarded.
# The first seconds are always lost while PIM registers the source with
# the RP and the receiver's join climbs the tree.
MIN_REPLIES=${MIN_REPLIES:-20}

# rp-lasthop: packets ED1 sends at one per second, how many of them have
# to make it to ED2, and how many registers R3 may decapsulate along the
# way.  R3 runs its SPT check every 10s (see write_configs), so it should
# join the shortest path tree and register-stop R1 within the first couple
# of intervals; one register per data packet is the failure the issue
# describes.
STREAM_PKTS=${STREAM_PKTS:-40}
MIN_RECEIVED=${MIN_RECEIVED:-20}
MAX_REGISTERS=${MAX_REGISTERS:-25}

# Seconds to let PIM settle before the gif-tunnel-staticrp stream, see
# check_gif_staticrp() for why that scenario needs it and the others do not.
SETTLE=${SETTLE:-45}

# ssm: two sources reported for one SSM group, and how long a membership
# then lives without a report.  IGMP_ROBUSTNESS_VARIABLE (3) *
# SSM_QUERY_INTERVAL + IGMP_QUERY_RESPONSE_INTERVAL (10), see r3.conf in
# write_configs().  SSM_SRC1 and SSM_SRC2 only have to be routable from
# R3, they never send: this scenario is about membership state, not
# forwarding.
SSM_QUERY_INTERVAL=${SSM_QUERY_INTERVAL:-5}
SSM_TIMEOUT=${SSM_TIMEOUT:-25}
SSM_SRC1=${SSM_SRC1:-10.0.1.10}
SSM_SRC2=${SSM_SRC2:-10.0.1.11}
SSM_MAX_SOURCES=${SSM_MAX_SOURCES:-256}

# gif-tunnel: the tunnel R1 and R3 build over R2.  The inner prefix is a
# /24 on a point-to-point link on purpose, see the header.
GIF_IF=gif0
GIF_R1=172.16.0.1
GIF_R3=172.16.0.2
GIF_MASK=255.255.255.0

die() { echo -n "EXIT: " >&2; echo "$@" >&2; exit 1; }
print() { printf "\033[7m>> %-76s\033[0m\n" "$1"; }
dprint() { printf "\033[2m%-76s\033[0m\n" "$1"; }

FAILED=0
XFAILED=0
ok()   { printf "  \033[32mok\033[0m    %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; FAILED=$((FAILED + 1)); }

# A behaviour that is wrong but known to be wrong: pimd deviates from the
# spec here, the scenario reproduces it on purpose, and the run is not red
# because of it.  It is still printed on every run, and the moment pimd
# starts doing the right thing the assertion that guards it turns into an
# ok and says so, which is the point of writing it down rather than
# leaving the case untested.
xfail() { printf "  \033[33mKNOWN\033[0m %s\n" "$1"; XFAILED=$((XFAILED + 1)); }

usage() {
	echo "usage: $0 start|check|run [rpt|keepalive|rp-lasthop|gif-tunnel|gif-tunnel-staticrp|shared-lan|shared-lan-spt|ssm] | run all | stop"
}

# Both shared segment scenarios are one topology.  They differ in whether
# the last hop router is allowed onto the shortest path tree, and therefore
# in which of the two contenders the spec says must win the assert.
is_shared_lan() {
	case $SCENARIO in
	shared-lan|shared-lan-spt) return 0 ;;
	esac

	return 1
}

set_scenario() {
	case ${1:-$SCENARIO} in
	rpt|keepalive|rp-lasthop|gif-tunnel|gif-tunnel-staticrp|shared-lan|shared-lan-spt|ssm)
		SCENARIO=${1:-$SCENARIO} ;;
	*) usage; exit 2 ;;
	esac

	# The shared segment scenarios have a topology of their own, five
	# routers over two bridges instead of three in a row
	if is_shared_lan; then
		BOXES=$SHARED_BOXES
		ROUTERS=$SHARED_ROUTERS
		EPAIRS="epair101 epair112 $SHARED_EPAIRS"
		ED2_IF=epair510b
	fi

	# gif-tunnel-staticrp copies the issue down to the addresses: the
	# KNX/IP group its reporters run, and the 224.0.0.0/16 rp-address
	# mask their pimd.conf uses, which only just covers that group.
	# 225.1.2.3, the group every other scenario uses, would fall
	# outside it and never resolve to an RP at all.
	if [ "$SCENARIO" = gif-tunnel-staticrp ]; then
		GROUP=${STATICRP_GROUP:-224.0.23.12}
	elif [ "$SCENARIO" = ssm ]; then
		# 232.0.0.0/8 is the SSM range, IN_PIM_SSM_RANGE() in
		# src/pimd.h, and the only range where pimd keeps a source
		# list per group at all
		GROUP=${SSM_GROUP:-232.1.1.1}
	else
		GROUP=$GROUP_DEFAULT
	fi
}

# Interfaces each box owns, "a" and "b" ends of the epairs above
ifaces() {
	if is_shared_lan; then
		# The bridged segments hand out "b" ends only, their "a" ends
		# stay on the host in $BR_UPSTREAM / $BR_RECEIVER
		case $1 in
		ed1) echo "epair101a" ;;
		r1)  echo "epair101b epair112a" ;;
		r2)  echo "epair112b epair223b" ;;
		r3)  echo "epair323b epair303b" ;;
		r4)  echo "epair423b epair403b" ;;
		r5)  echo "epair503b epair510a" ;;
		ed2) echo "epair510b" ;;
		ed3) echo "epair603b" ;;
		esac
		return
	fi

	case $1 in
	ed1) echo "epair101a" ;;
	r1)  echo "epair101b epair112a" ;;
	r2)  echo "epair112b epair123a" ;;
	r3)  echo "epair123b epair203a" ;;
	ed2) echo "epair203b" ;;
	esac
}

# Interfaces renamed once the jail owns them, "<old> <new>" pairs.
#
# R2's link to R1 deliberately carries an uppercase letter, and r2.conf
# then names that interface in its bsr-candidate and rp-candidate lines.
# pimd lowercases every token it reads from the .conf (next_word() in
# src/config.c), while the kernel keeps the name as it is, so a
# case-sensitive lookup silently fails to resolve the interface: pimd
# falls back to the highest active address and advertises the wrong RP.
# Assertion 3 catches that, because it demands the RP be $RP_ADDR rather
# than whatever address happens to be numerically highest.
# See https://github.com/troglobit/pimd/pull/252.
renames() {
	case $1 in
	r2) echo "epair112b Epair112b" ;;
	*)  echo "" ;;
	esac
}

# "<interface> <address>/<prefixlen>" pairs to configure per box
addrs() {
	if is_shared_lan; then
		case $1 in
		ed1) echo "epair101a 10.0.1.10/24" ;;
		r1)  echo "epair101b 10.0.1.1/24 epair112a 10.0.12.1/24" ;;
		r2)  echo "Epair112b 10.0.12.2/24 epair223b 10.0.23.2/24" ;;
		r3)  echo "epair323b 10.0.23.3/24 epair303b $SL_R3_ADDR/24" ;;
		r4)  echo "epair423b 10.0.23.4/24 epair403b $SL_DR_ADDR/24" ;;
		r5)  echo "epair503b $SL_QUERIER_ADDR/24 epair510a 10.0.5.1/24" ;;
		ed2) echo "epair510b 10.0.5.10/24" ;;
		ed3) echo "epair603b $SL_ED3_ADDR/24" ;;
		esac
		return
	fi

	case $1 in
	ed1) echo "epair101a 10.0.1.10/24" ;;
	r1)  echo "epair101b 10.0.1.1/24 epair112a 10.0.12.1/24" ;;
	r2)  echo "Epair112b 10.0.12.2/24 epair123a 10.0.23.2/24" ;;
	r3)  echo "epair123b 10.0.23.3/24 epair203a 10.0.3.1/24" ;;
	ed2) echo "epair203b 10.0.3.10/24" ;;
	esac
}

# Routers that run pimd.  gif-tunnel leaves R2 as a plain unicast transit
# router with no pimd at all, which is the whole point: it stands in for
# the network between two VPN endpoints, and PIM only ever meets it as
# the carrier of the gif outer packets.
pim_routers() {
	case $SCENARIO in
	gif-tunnel|gif-tunnel-staticrp) echo "r1 r3" ;;
	*)                              echo "$ROUTERS" ;;
	esac
}

# gif tunnels to build inside a box, as
# "<ifname> <outer-local> <outer-remote> <inner-local> <inner-remote>".
# Only gif-tunnel has any; the outer addresses are the ones R2 already
# routes between, so the tunnel needs no extra plumbing of its own.
tunnels() {
	case $SCENARIO in
	gif-tunnel|gif-tunnel-staticrp) ;;
	*) return 0 ;;
	esac

	case $1 in
	r1) echo "$GIF_IF 10.0.12.1 10.0.23.3 $GIF_R1 $GIF_R3" ;;
	r3) echo "$GIF_IF 10.0.23.3 10.0.12.1 $GIF_R3 $GIF_R1" ;;
	esac
}

# Static unicast routes, "<destination> <gateway>" pairs.  pimd needs a
# unicast RPF answer for every source and for the RP.
routes() {
	# gif-tunnel: R1 and R3 reach each other's LAN through the tunnel,
	# so that is where their RPF lookups land, while the underlay
	# routes stay put to carry the gif outer packets through R2.
	case $SCENARIO in
	gif-tunnel|gif-tunnel-staticrp)
		case $1 in
		ed1) echo "default 10.0.1.1" ;;
		r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 $GIF_R3" ;;
		r2)  echo "10.0.1.0/24 10.0.12.1 10.0.3.0/24 10.0.23.3" ;;
		r3)  echo "10.0.12.0/24 10.0.23.2 10.0.1.0/24 $GIF_R1" ;;
		ed2) echo "default 10.0.3.1" ;;
		esac
		return ;;
	shared-lan|shared-lan-spt)
		# R5 reaches the source and the RP through R3, which is what
		# makes this scenario work: its Join names R3 as the upstream
		# router, and receive_pim_join_prune() (src/pim_proto.c) only
		# lets the router named in the Join add the oif, everyone else
		# on the LAN uses it for suppression.  R3 therefore forwards
		# because of R5's Join and R4 because of ED3's IGMP report,
		# and the LAN has the two forwarders an assert needs.
		#
		# R2 reaches everything behind the LAN through R4, so the
		# reverse direction (ED2's mping replies climbing back to the
		# RP) uses the same router as the forward one.  Pointed at R3
		# instead, the RP would pull the replies through the router
		# that loses the assert and the two directions would settle
		# independently - legal, but one more thing to explain when a
		# count comes out wrong.
		case $1 in
		ed1) echo "default 10.0.1.1" ;;
		r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2 10.0.5.0/24 10.0.12.2" ;;
		r2)  echo "10.0.1.0/24 10.0.12.1 10.0.3.0/24 10.0.23.4 10.0.5.0/24 10.0.23.4" ;;
		r3)  echo "10.0.1.0/24 10.0.23.2 10.0.12.0/24 10.0.23.2 10.0.5.0/24 $SL_QUERIER_ADDR" ;;
		r4)  echo "10.0.1.0/24 10.0.23.2 10.0.12.0/24 10.0.23.2 10.0.5.0/24 $SL_QUERIER_ADDR" ;;
		r5)  echo "10.0.1.0/24 $SL_R3_ADDR 10.0.12.0/24 $SL_R3_ADDR 10.0.23.0/24 $SL_R3_ADDR" ;;
		ed2) echo "default 10.0.5.1" ;;
		ed3) echo "default $SL_DR_ADDR" ;;
		esac
		return ;;
	esac

	case $1 in
	ed1) echo "default 10.0.1.1" ;;
	r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2" ;;
	r2)  echo "10.0.1.0/24 10.0.12.1 10.0.3.0/24 10.0.23.3" ;;
	r3)  echo "10.0.1.0/24 10.0.23.2 10.0.12.0/24 10.0.23.2" ;;
	ed2) echo "default 10.0.3.1" ;;
	esac
}

jname() { echo "pimd_$1"; }

jrun() { j=$1; shift; ${SUDO} jexec "$(jname "$j")" "$@"; }

pimctl() { j=$1; shift; jrun "$j" "$PIMCTL" -u "$WORKDIR/$j.sock" "$@"; }

# Retry a command until it succeeds or $1 seconds have passed.  PIM is
# slow by design (hello 30s, bootstrap 60s; shortened in the configs
# below), so every assertion polls instead of sleeping a fixed amount.
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
	[ -f "$PIMD_SRC/test/igmpv3.c" ] || die "$PIMD_SRC/test/igmpv3.c not found"
	# ip_mroute is a module on GENERIC and a jail may not kldload
	${SUDO} kldload -n ip_mroute 2>/dev/null || \
		die "cannot load ip_mroute.ko, kernel has no multicast routing"
}

# net.inet.ip.mcast.loop must be 0 for any PIM router on FreeBSD.
#
# phyint_send() in sys/netinet/ip_mroute.c copies the sysctl into every
# packet it forwards (imo.imo_multicast_loop = !!in_mcast_loop), and
# ip_output() then loops that packet straight back into ip_input() -
# "even if we are not a member of the group".  The router therefore
# receives its own forwarded traffic on the interface it just sent it
# out of, ip_mdq() raises IGMPMSG_WRONGVIF for it, and pimd answers the
# wrong-iif upcall with a PIM Assert.  The neighbour asserts back, pimd
# loses the election against itself and prunes the oif, which installs an
# MFC entry with an empty outgoing interface list and black-holes the
# group.  Measured here: 4 of 60 packets delivered with the sysctl at its
# default of 1, 40 of 40 with it set to 0.
#
# The sysctl is a plain global, not VNET-ized (in_mcast_loop in
# sys/netinet/in_mcast.c has no CTLFLAG_VNET), so it cannot be set per
# jail: the value has to be changed on the host, and is restored by stop.
MCAST_LOOP_SAVED="$WORKDIR/mcast_loop.saved"

disable_mcast_loop() {
	sysctl -n net.inet.ip.mcast.loop > "$MCAST_LOOP_SAVED"
	${SUDO} sysctl -q net.inet.ip.mcast.loop=0
}

restore_mcast_loop() {
	[ -f "$MCAST_LOOP_SAVED" ] || return 0
	${SUDO} sysctl -q net.inet.ip.mcast.loop="$(cat "$MCAST_LOOP_SAVED")"
}

# R2 is the only BSR and RP candidate, pinned to its 10.0.12.2 address so
# the RP address does not depend on interface ordering.  The intervals are
# the RFC minimum (10s) rather than the 60s default, and spt-threshold is
# low, so the lab converges in tens of seconds instead of minutes.
# spt-threshold is deliberately left at the pimd default (switch to the
# shortest path tree on the first packet).  Setting it to a non-zero
# packet count instead makes the routers switch away from the shared tree
# in the middle of the measured stream, and the traffic then stalls for
# one Join/Prune period (~60s) before it recovers - real behaviour, but it
# belongs in an SPT-specific test, not in this one.
#
# The keepalive scenario moves both candidacies to R1, so the router that
# is DR for $SRC_ADDR is also the RP for the groups that source sends to.
# It also asks for spt-threshold infinity, like the pimd.conf in issue
# #251, to keep the RP on the shared tree.
write_configs() {
	if [ "$SCENARIO" = keepalive ]; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: DR for $SRC_ADDR *and* RP for the groups it sends to
		spt-threshold infinity
		bsr-candidate epair101b priority 1 interval 10
		rp-candidate epair101b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		: > "$WORKDIR/r2.conf"
		: > "$WORKDIR/r3.conf"
		return
	fi

	if [ "$SCENARIO" = ssm ]; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for the reported sources
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: bootstrap router and rendezvous point.  Not used by an
		# SSM group, which never has a shared tree, but the domain
		# needs one for pimd to consider itself converged
		bsr-candidate Epair112b priority 1 interval 10
		rp-candidate Epair112b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		# The membership timeout is
		# IGMP_ROBUSTNESS_VARIABLE * igmp_query_interval +
		# IGMP_QUERY_RESPONSE_INTERVAL (src/igmp_proto.c), 385s at the
		# default query interval.  Nothing in this scenario is worth
		# waiting six minutes for, so the interval is cut to 5s and the
		# timeout with it, to $SSM_TIMEOUT.
		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: last hop router for the receiver LAN
		igmp-query-interval $SSM_QUERY_INTERVAL
		EOF
		return
	fi

	if [ "$SCENARIO" = rp-lasthop ]; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, no BSR/RP role
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: plain transit router between the source and the RP
		EOF

		# The candidacies are pinned to epair203a so the RP address is
		# $RPLH_ADDR, R3's own receiver LAN interface: R3 is then the RP
		# for a group it also has a directly connected member for, and
		# set_incoming() gives its (*,G) the register vif as incoming
		# interface (PIM_IIF_RP in src/route.c).  That is the state
		# router A shows in issue #243.
		#
		# The issue's own configs use a static "rp-address" instead.
		# Not reused here: my_cand_rp_address is only assigned when
		# parsing cand_rp (src/config.c), so with a static RP the
		# register vif check in process_cache_miss() (src/route.c) would
		# make R3 encapsulate its own receiver's mping replies to
		# itself, which is extra traffic in the trace and not what this
		# scenario is about.
		# spt-threshold is left in its default mode (switch on the
		# first packet) but its interval is cut from the default 100s
		# down to 10s, and that is not cosmetic.  On the RP the decision
		# to stop decapsulating and pull the source onto a native path
		# is only ever taken from check_spt_threshold(), and the only
		# caller that runs while traffic flows is age_routes(), gated on
		# pim_spt_threshold_timer (rate_flag in src/route.c).  The
		# cache-miss path cannot do it: the first packet installs a
		# kernel MFC entry, so the kernel never upcalls again.  With the
		# 100s default and a 40s stream the timer fires inside the
		# measurement window or it does not, and this scenario passes or
		# fails on that phase alone - observed both ways on the same
		# lab, 3 registers in one run and 41 in the next.  At 10s it has
		# to fire, so a failure here is pimd, not timer luck.
		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: bootstrap router, rendezvous point *and* last hop router
		bsr-candidate epair203a priority 1 interval 10
		rp-candidate epair203a priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		spt-threshold packets 0 interval 10
		EOF
		return
	fi

	if [ "$SCENARIO" = gif-tunnel-staticrp ]; then
		# The same tunnel as gif-tunnel, but the RP is configured
		# statically on both ends instead of being elected, which is
		# how every pimd.conf quoted in #243 is written.
		#
		# That is not just a different route to the same state.
		# my_cand_rp_address is only ever assigned while parsing
		# cand_rp (src/config.c), never by parse_rp_address(), so on
		# a static RP it stays 0.0.0.0 and every "am I the RP?" test
		# written against it is false on the very router that is the
		# RP.  Two of those matter here:
		#
		#   process_cache_miss() (src/route.c) adds the register vif
		#   to the oif list of a directly connected source unless
		#   group->rpaddr == my_cand_rp_address, so R3 encapsulates
		#   its own receiver's traffic towards itself.
		#
		#   join_or_prune() (src/pim_proto.c) returns PIM_ACTION_PRUNE
		#   instead of PIM_ACTION_NOTHING for an (S,G) with an empty
		#   oif list at the RP, i.e. the RP prunes the source it just
		#   joined.
		#
		# spt-threshold keeps the 10s interval of the other gif
		# scenario so the result does not depend on timer phase.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, tunnel endpoint
		phyint epair101b enable
		phyint $GIF_IF enable
		phyint epair112a disable
		rp-address $RPLH_ADDR 224.0.0.0/16
		EOF

		: > "$WORKDIR/r2.conf"

		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: tunnel endpoint, static RP, and last hop router
		phyint epair203a enable
		phyint $GIF_IF enable
		phyint epair123b disable
		rp-address $RPLH_ADDR 224.0.0.0/16
		spt-threshold packets 0 interval 10
		EOF
		return
	fi

	if [ "$SCENARIO" = gif-tunnel ]; then
		# PIM runs on the LAN and on the tunnel only.  The underlay
		# interface is explicitly disabled rather than just left
		# without a neighbour: that is how the pfSense and Raspberry
		# Pi configs in the issue are written, and it keeps the RPF
		# answer for the remote LAN unambiguously $GIF_IF.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, tunnel endpoint
		phyint epair101b enable
		phyint $GIF_IF enable
		phyint epair112a disable
		EOF

		: > "$WORKDIR/r2.conf"

		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: tunnel endpoint, RP, and last hop router for $RCV_ADDR
		phyint epair203a enable
		phyint $GIF_IF enable
		phyint epair123b disable
		bsr-candidate epair203a priority 1 interval 10
		rp-candidate epair203a priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		spt-threshold packets 0 interval 10
		EOF
		return
	fi

	if is_shared_lan; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, no BSR/RP role
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: bootstrap router and rendezvous point, one hop upstream
		# of the shared segment.  Epair112b is spelled with an
		# uppercase letter on purpose, see renames()
		bsr-candidate Epair112b priority 1 interval 10
		rp-candidate Epair112b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		# Every router on the shared segment is pinned to the shared
		# tree for the whole run.  Left at the pimd default they switch
		# to the shortest path tree somewhere inside the measured
		# stream, each on its own timer phase, and the assert election
		# is then between two entries whose RPT bits differ: the RPT
		# bit is the most significant bit of the assert preference, so
		# the winner is decided by which router switched first rather
		# than by the address.  Held on the shared tree both advertise
		# the same preference and metric and compare_metrics()
		# (src/pim_proto.c) falls through to the address, which does
		# not change between runs.
		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: upstream router for R5 on the shared LAN ($SL_R3_ADDR),
		# neither its DR nor its querier
		spt-threshold infinity
		EOF

		cat <<-EOF > "$WORKDIR/r4.conf"
		# R4: PIM DR on the shared LAN ($SL_DR_ADDR, highest address),
		# so ED3's IGMP report is its leaf and nobody else's
		spt-threshold infinity
		EOF

		# R5 is the only router here that may switch to the shortest
		# path tree at all: try_switch_to_spt() (src/route.c) runs only
		# for MRT_IS_LASTHOP or MRT_IS_RP, and R5 is the one with a
		# leaf.  Whether it does is the whole difference between the
		# two scenarios.
		#
		# shared-lan holds it on the shared tree, so both contenders
		# are RPT forwarders and the assert is symmetric.
		#
		# shared-lan-spt lets it switch, and its interval is cut from
		# the 100s default to 10s because the decision is only ever
		# taken from age_routes() gated on pim_spt_threshold_timer: at
		# the default the switch lands inside the measured stream or
		# after it depending on timer phase.  When it fires,
		# switch_shortest_path() (src/route.c) fires the Join/Prune
		# timer and R5 sends an (S,G) Join to its RPF neighbour towards
		# $SRC_ADDR, which is R3.  R3 then has genuine (S,G) forwarding
		# state and R4, which only ever had ED3's (*,G) leaf, does not.
		if [ "$SCENARIO" = shared-lan-spt ]; then
			cat <<-EOF > "$WORKDIR/r5.conf"
			# R5: last hop router for ED2, and the only router here
			# allowed to pull the group onto the shortest path tree
			spt-threshold packets 0 interval 10
			EOF
			return
		fi

		cat <<-EOF > "$WORKDIR/r5.conf"
		# R5: last hop router for ED2, IGMP querier on the shared LAN
		# ($SL_QUERIER_ADDR, lowest address), and the downstream router
		# whose Join gives R3 an oif there
		spt-threshold infinity
		EOF
		return
	fi

	cat <<-EOF > "$WORKDIR/r1.conf"
	# R1: first hop router for $SRC_ADDR, no BSR/RP role
	EOF

	cat <<-EOF > "$WORKDIR/r2.conf"
	# R2: bootstrap router and rendezvous point for all of 224.0.0.0/4
	# Epair112b is spelled with an uppercase letter on purpose, see renames()
	bsr-candidate Epair112b priority 1 interval 10
	rp-candidate Epair112b priority 20 interval 10
	group-prefix 224.0.0.0 masklen 4
	EOF

	cat <<-EOF > "$WORKDIR/r3.conf"
	# R3: last hop router for the receiver LAN
	EOF
}

# A sender that never joins anything: sends $KEEP_NUM UDP streams to
# consecutive groups starting at $KEEP_GROUP, five packets per second
# each, until it is killed.
build_msend() {
	cat <<-'EOF' > "$WORKDIR/msend.c"
	#include <arpa/inet.h>
	#include <netinet/in.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <sys/socket.h>
	#include <time.h>

	int main(int argc, char *argv[])
	{
		struct sockaddr_in sin;
		struct in_addr ifa;
		unsigned char ttl = 5;
		char buf[64] = "msend";
		uint32_t base;
		int sd, i, num;

		if (argc != 4) {
			fprintf(stderr, "usage: %s <src-ip> <first-group> <num>\n", argv[0]);
			return 1;
		}

		if (inet_pton(AF_INET, argv[1], &ifa) != 1)
			return 1;
		if (inet_pton(AF_INET, argv[2], &sin.sin_addr) != 1)
			return 1;
		base = ntohl(sin.sin_addr.s_addr);
		num = atoi(argv[3]);

		sd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sd < 0)
			return 1;
		if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &ifa, sizeof(ifa)))
			return 1;
		setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(4321);

		while (1) {
			struct timespec ts = { 0, 200000000L };

			for (i = 0; i < num; i++) {
				sin.sin_addr.s_addr = htonl(base + i);
				sendto(sd, buf, sizeof(buf), 0,
				       (struct sockaddr *)&sin, sizeof(sin));
			}
			nanosleep(&ts, NULL);
		}

		return 0;
	}
	EOF

	cc -O2 -o "$MSEND" "$WORKDIR/msend.c" || die "failed building $WORKDIR/msend.c"
}

# shared-lan: the two bridged segments.  Each is a host bridge holding the
# "a" end of every epair on it while the "b" ends go into the jails, so the
# boxes really do share one broadcast domain instead of meeting over a mesh
# of point-to-point links.  The bridges live on the host rather than in a
# jail of their own because a jail cannot kldload if_bridge, and they carry
# no addresses: the host is a wire here, not a router.
create_lans() {
	is_shared_lan || return 0

	for br in $BR_UPSTREAM $BR_RECEIVER; do
		if ifconfig "$br" >/dev/null 2>&1; then
			die "$br already exists, it is not ours to reuse"
		fi
	done

	${SUDO} kldload -n if_bridge 2>/dev/null || \
		die "cannot load if_bridge.ko, needed for the shared segments"

	${SUDO} ifconfig "$BR_UPSTREAM" create group pimd up >/dev/null
	${SUDO} ifconfig "$BR_RECEIVER" create group pimd up >/dev/null

	for e in $BR_UPSTREAM_EPAIRS $BR_RECEIVER_EPAIRS; do
		${SUDO} ifconfig "$e" create group pimd >/dev/null
		${SUDO} ifconfig "${e}a" up
	done

	for e in $BR_UPSTREAM_EPAIRS; do
		${SUDO} ifconfig "$BR_UPSTREAM" addm "${e}a"
	done
	for e in $BR_RECEIVER_EPAIRS; do
		${SUDO} ifconfig "$BR_RECEIVER" addm "${e}a"
	done
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
		# The "a" end creates both ends of the pair
		case $i in
		*a) ${SUDO} ifconfig "${i%a}" create group pimd >/dev/null ;;
		esac
		vnetargs="$vnetargs vnet.interface=$i"
	done

	# shellcheck disable=SC2086
	${SUDO} jail -c name="$name" host.hostname="$box" persist vnet $vnetargs

	set -- $(renames "$box")
	while [ $# -ge 2 ]; do
		jrun "$box" ifconfig "$1" name "$2"
		shift 2
	done

	set -- $(addrs "$box")
	while [ $# -ge 2 ]; do
		jrun "$box" ifconfig "$1" inet "$2" up
		shift 2
	done

	# Before the routes: gif-tunnel points some of them at $GIF_R1/$GIF_R3
	set -- $(tunnels "$box")
	while [ $# -ge 5 ]; do
		jrun "$box" ifconfig "$1" create
		jrun "$box" ifconfig "$1" tunnel "$2" "$3"
		jrun "$box" ifconfig "$1" inet "$4" "$5" netmask "$GIF_MASK" up
		shift 5
	done

	set -- $(routes "$box")
	while [ $# -ge 2 ]; do
		jrun "$box" route -q add "$1" "$2" >/dev/null
		shift 2
	done

	case $box in
	r*) jrun "$box" sysctl -q net.inet.ip.forwarding=1 >/dev/null ;;
	esac
}

destroy_box() {
	box=$1
	name=$(jname "$box")

	jls -j "$name" jid >/dev/null 2>&1 || return 0
	${SUDO} jail -r "$name" 2>/dev/null || true
}

start() {
	check_req

	if jls -j "$(jname r1)" jid >/dev/null 2>&1; then
		die "lab already running, run '$0 stop' first"
	fi

	# Owned by the invoking user: pimd runs as root and can still drop its
	# PID file and control socket in here, but mping is built unprivileged.
	mkdir -p "$WORKDIR"

	print "Building mping (multicast ping) from the pimd tree ..."
	cc -O2 -o "$MPING" "$PIMD_SRC/test/mping.c" || \
		die "failed building $PIMD_SRC/test/mping.c"

	print "Building igmpv3 (membership report generator) ..."
	cc -O2 -o "$IGMPV3" "$PIMD_SRC/test/igmpv3.c" || \
		die "failed building $PIMD_SRC/test/igmpv3.c"

	print "Disabling multicast loopback on the host (restored by stop) ..."
	disable_mcast_loop

	print "Creating vnet jails and links ..."
	write_configs
	create_lans
	for box in $BOXES; do
		create_box "$box"
	done

	print "Starting pimd on $(pim_routers | tr ' ' ',') ..."
	for r in $(pim_routers); do
		# shellcheck disable=SC2086
		${SUDO} daemon -f -p "$WORKDIR/$r.daemon.pid" \
			-o "$WORKDIR/$r.log" \
			jexec "$(jname "$r")" "$PIMD" -i "$r" -n $DEBUG \
			-f "$WORKDIR/$r.conf" \
			-p "$WORKDIR/$r.pid" \
			-u "$WORKDIR/$r.sock"
	done

	if [ "$SCENARIO" = keepalive ]; then
		print "Starting the source on ED1, $KEEP_NUM groups from $KEEP_GROUP ..."
		build_msend
		${SUDO} daemon -f -p "$WORKDIR/msend.pid" -o "$WORKDIR/msend.log" \
			jexec "$(jname ed1)" "$MSEND" "$SRC_ADDR" "$KEEP_GROUP" "$KEEP_NUM"
	fi

	print "Lab is up ($SCENARIO).  Poke at it with:"
	echo "  ${SUDO} jexec $(jname r2) $PIMCTL -u $WORKDIR/r2.sock show pim detail"
	echo "  ${SUDO} jexec $(jname r3) netstat -gn"
	echo "  ${SUDO} jexec $(jname ed2) $MPING -r -i $ED2_IF $GROUP"
	echo "  tail -f $WORKDIR/r1.log"
}

# --- assertions -------------------------------------------------------

has_neighbor() { pimctl "$1" show neighbor 2>/dev/null | grep -q "$2"; }
has_iface()    { pimctl "$1" show interface 2>/dev/null | grep -q "^$2 "; }

# config_vifs_from_kernel() logs a point-to-point vif as "(local -> peer)"
# and an ordinary one as "(local on subnet X)", and only the first branch
# sets VIFF_POINT_TO_POINT | VIFF_REXMIT_PRUNES and takes uv_rmt_addr from
# ifa_dstaddr (src/config.c).  Asserting on the wording is crude but it is
# the only externally visible difference, and without it the gif scenario
# would still pass if the tunnel ever came up as a plain subnet vif, i.e.
# while testing nothing it claims to test.
took_p2p_branch() {
	${SUDO} grep -q "Installing $GIF_IF ($2 -> $3)" "$WORKDIR/$1.log" 2>/dev/null
}
has_rp()       { pimctl "$1" show rp 2>/dev/null | grep -q "$2"; }
has_mrt()      { pimctl "$1" show mrt 2>/dev/null | grep -q "$2"; }
has_mfc()      { jrun "$1" netstat -gn 2>/dev/null | grep -q "$2"; }

# Every (S,G) the source is sending to, one per line, as pimctl shows them
sources() { pimctl r1 show mrt 2>/dev/null | awk -v s="$SRC_ADDR" '$1 == s { print $2 }'; }
all_sources_up() { [ "$(sources | wc -l)" -eq "$KEEP_NUM" ]; }

# "<group> <entry timer>" per (S,G), read out of the detailed dump.  The
# entry timer is the only reliable witness: an entry that is recreated by
# the next cache miss 1.5s later looks exactly like one that was never
# deleted if all you count is table rows, but a recreated entry always
# comes back with its timer at 0.
source_timers() {
	pimctl r1 show mrt detail 2>/dev/null | awk -v s="$SRC_ADDR" '
		$1 == s   { grp = $2; next }
		grp == "" { next }
		/TIMERS/  { want = 1; next }
		want      { print grp, $1; grp = ""; want = 0 }
	'
}

# Vif index of the incoming interface of ($2,$3) on router $1, or nothing
# when there is no such entry.  "pimctl show mrt detail" prints the iif as
# a per-vif map, one character per vif with 'I' on the incoming one
# ("Incoming     : .I.."), so the offset of the 'I' is the vif number.
# Vif 0 is always the register vif, PIMREG_VIF in src/vif.h reserves it.
route_iif() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" '
		$1 == s && $2 == g { want = 1; next }
		want && $1 == "Incoming" { print index($3, "I") - 1; want = 0 }
	'
}

# PIM registers R3 has decapsulated so far.  One per data packet means the
# RP never got off the register vif; a handful means it register-stopped
# the first hop router early, as it should.
registers_seen() {
	${SUDO} grep -c "Received PIM register:" "$WORKDIR/r3.log" 2>/dev/null || true
}

# The "Outgoing oifs" map of ($2,$3) on router $1, same one-character-per-vif
# encoding as route_iif(), so position 0 is the register vif.
route_oifs() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" '
		$1 == s && $2 == g { want = 1; next }
		want && $1 == "Outgoing" { print $3; want = 0 }
	'
}

has_static_rp() { pimctl "$1" show rp 2>/dev/null | grep "$2" | grep -q Static; }

# Any of the per-vif maps of ($2,$3) on router $1, named by the first word
# of its line in "show mrt detail": Joined, Pruned, Leaves, Asserted or
# Outgoing.  Same one-character-per-vif encoding as route_oifs().
route_map() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" -v k="$4" '
		$1 == s && $2 == g { want = 1; next }
		want && $1 == k    { print $3; want = 0 }
	'
}

# Vif index of interface $2 on router $1.  "show interface" prints one row
# per vif in vif order and skips the register vif, which src/vif.h reserves
# as vif 0 (PIMREG_VIF), so the Nth row is vif N.  -t drops both table
# headings, leaving nothing but the rows.
vif_index() {
	pimctl "$1" -t show interface 2>/dev/null | \
		awk -v ifn="$2" 'NF { n++; if ($1 == ifn) { print n; exit } }'
}

# Is the slot interface $2 owns set in the map $3 read out of router $1?
map_isset() {
	idx=$(vif_index "$1" "$2")
	[ -n "$idx" ] || return 1
	[ -n "$3" ] || return 1

	[ "$(printf '%s' "$3" | cut -c "$((idx + 1))")" != "." ]
}

# Does router $1 forward this scenario's stream onto interface $2, and has
# it been asserted off it?
#
# Forwarding is read out of the kernel rather than out of pimd, because
# neither pimd entry answers it on its own: a router that lost the assert
# can still show the LAN in the oifs of its (*,G), which is state about the
# group and not about this source, and a router that won can be forwarding
# off a kernel cache hung on its (*,G) with no (S,G) of its own to read.
# The MFC is the forwarding decision itself, and its vif numbers are the
# ones pimd handed the kernel, so vif_index() maps names onto them.
#
# Asserted state is read off both entries, since which one the assert
# landed on depends on what the router held when it arrived.
forwards_on() {
	idx=$(vif_index "$1" "$2")
	[ -n "$idx" ] || return 1

	jrun "$1" netstat -gn 2>/dev/null | awk -v s="$SRC_ADDR" -v g="$3" -v v="$idx" '
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

asserted_on() {
	for src in ANY "$SRC_ADDR"; do
		if map_isset "$1" "$2" "$(route_map "$1" "$src" "$3" Asserted)"; then
			return 0
		fi
	done

	return 1
}

# Has router $1 joined group $3 towards interface $2?  Re-read on every
# call, so it can be polled with wait_for().
joined_on() {
	map_isset "$1" "$2" "$(route_map "$1" ANY "$3" Joined)"
}

# The DR address pimd shows for interface $2 on router $1.  A router that is
# the DR itself prints its own address here (show_interface() in src/ipc.c).
iface_dr() {
	pimctl "$1" -t show interface 2>/dev/null | \
		awk -v ifn="$2" '$1 == ifn { print $7; exit }'
}

# The IGMP querier pimd shows for interface $2 on router $1, "Local" when
# this router won the election.  "show igmp" prints an interface table and a
# group table, both keyed on the interface name and both stripped of their
# headings by -t, so the rows are told apart by the interface state in the
# second column.
iface_querier() {
	pimctl "$1" -t show igmp 2>/dev/null | \
		awk -v ifn="$2" '$1 == ifn && $2 ~ /^(Up|Down|Disabled)$/ { print $3; exit }'
}

# Run the ED1 -> ED2 stream and watch the RP while it is in flight.
# Sets: replies, regs, sg_seen, sg_native, selfreg.
#
# The sampling has to happen during the stream.  Killing the receiver
# expires ED2's membership within seconds, the (*,G) loses its leaf and
# the (S,G) is rebuilt or aged out, so a dump taken afterwards describes a
# different router than the one under test.
#
# Vif 0 is the register vif, PIMREG_VIF in src/vif.h reserves it.  An
# (S,G) still incoming on vif 0 means the RP is living off the
# encapsulated copies alone and never joined the shortest path tree
# towards the source, which is the state router A shows in #243.
run_stream_and_sample() {
	regs_before=$(registers_seen)
	jrun ed1 "$MPING" -s -i epair101a -t 5 -c "$STREAM_PKTS" -w 90 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 &
	sender=$!

	sg_seen=
	sg_native=
	selfreg=
	deadline=$(($(date +%s) + STREAM_PKTS + 30))
	while [ "$(date +%s)" -lt "$deadline" ]; do
		# Does the RP encapsulate its own directly connected source
		# towards itself?  Sampled every round, because it shows up
		# as soon as ED2 answers, well before the loop breaks below.
		case $(route_oifs r3 "$RCV_ADDR" "$GROUP") in
		o*) selfreg=yes ;;
		esac

		sg_iif=$(route_iif r3 "$SRC_ADDR" "$GROUP")
		if [ -n "$sg_iif" ]; then
			sg_seen=$sg_iif
			if [ "$sg_iif" -ne 0 ]; then
				sg_native=$sg_iif
				break
			fi
		fi
		sleep 1
	done

	wait "$sender" 2>/dev/null || true
	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true
	regs=$(( $(registers_seen) - regs_before ))

	# Counted from the replies, not from the receiver's own log: mping
	# writes that log through a block buffered stdout and it is killed,
	# not stopped, so the buffer never reaches the disk.  A reply only
	# exists because a packet arrived at ED2, so the count is still a
	# lower bound on what the #243 direction delivered.
	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
}

# shared-lan: run the ED1 -> ED2 stream, then read the receiver LAN state
# off both last hop routers.  Sets: replies, fwd3, fwd4, ast3, ast4, reg3.
#
# The sampling happens after the sender is done but while the receiver is
# still joined, which is the only window where the answer means anything:
# the first packets of the stream are forwarded by both routers by
# definition, that duplicate is what triggers the assert, so sampling early
# reports a race rather than a result; and killing the receiver expires
# ED2's membership within seconds, after which both routers drop the leaf
# and the assert state goes with it.
run_stream_and_sample_shared() {
	jrun ed1 "$MPING" -s -i epair101a -t 5 -c "$STREAM_PKTS" -w 90 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 || true

	fwd3=
	fwd4=
	ast3=
	ast4=
	reg3=
	if forwards_on r3 "$SL_R3_IF" "$GROUP"; then fwd3=yes; fi
	if forwards_on r4 "$SL_R4_IF" "$GROUP"; then fwd4=yes; fi
	if asserted_on r3 "$SL_R3_IF" "$GROUP"; then ast3=yes; fi
	if asserted_on r4 "$SL_R4_IF" "$GROUP"; then ast4=yes; fi

	# Did R5's switch actually reach R3, i.e. does R3 hold (S,G) forwarding
	# state of its own?  Without this the assert outcome below could not be
	# read: a run where R5 never switched has two RPT forwarders and says
	# nothing about which tree the election preferred.
	sg3=
	if map_isset r3 "$SL_R3_IF" "$(route_map r3 "$SRC_ADDR" "$GROUP" Joined)"; then
		sg3=yes
	fi

	# Vif 0 is the register vif.  R3 is not the DR for the shared LAN, so
	# process_cache_miss() (src/route.c) must never add it to the oifs of
	# a source sitting there - registering ED3 is R4's job.
	case $(route_oifs r3 "$SL_ED3_ADDR" "$GROUP") in
	o*) reg3=yes ;;
	esac

	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true

	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
}

check() {
	jls -j "$(jname r1)" jid >/dev/null 2>&1 || die "lab is not running, run '$0 start'"

	# "run all" walks the scenarios in one shell, and every check_*()
	# gates its later assertions on "[ $FAILED -eq 0 ] || return 1".
	# Without this the first scenario to fail takes every scenario after
	# it down at its first checkpoint, with all of their assertions
	# printing ok on the way out - a clean looking run that tested
	# nothing.
	FAILED=0
	XFAILED=0

	case $SCENARIO in
	keepalive)  check_keepalive; return $? ;;
	rp-lasthop) check_rp_lasthop; return $? ;;
	gif-tunnel) check_gif_tunnel; return $? ;;
	gif-tunnel-staticrp) check_gif_staticrp; return $? ;;
	shared-lan|shared-lan-spt) check_shared_lan; return $? ;;
	ssm)        check_ssm; return $? ;;
	esac

	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if pimctl "$r" show status >/dev/null 2>&1; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. PIM neighbors are discovered over the epairs"
	if wait_for 60 has_neighbor r1 10.0.12.2; then
		ok "r1 sees r2 (10.0.12.2)"
	else
		fail "r1 never saw r2, PIM hello is not crossing epair112"
	fi
	if wait_for 60 has_neighbor r2 10.0.23.3; then
		ok "r2 sees r3 (10.0.23.3)"
	else
		fail "r2 never saw r3, PIM hello is not crossing epair123"
	fi
	if wait_for 60 has_neighbor r3 10.0.23.2; then
		ok "r3 sees r2 (10.0.23.2)"
	else
		fail "r3 never saw r2"
	fi

	print "3. The RP set is distributed by the bootstrap router"
	for r in $ROUTERS; do
		if wait_for 90 has_rp "$r" "$RP_ADDR"; then
			ok "$r learned RP $RP_ADDR"
		else
			fail "$r never learned RP $RP_ADDR (BSR/cand-RP path)"
		fi
	done

	# mping echoes every packet back to the group, so a reply proves both
	# the (10.0.1.10,G) tree towards ED2 and the (10.0.3.10,G) tree back.
	# Its own exit code demands *every* packet be answered, which no PIM
	# network can do while it is still converging - the first packets are
	# what builds the tree.  Count the replies instead and require the
	# stream to be flowing rather than perfect.
	print "4. Multicast is forwarded from ED1 to ED2 through the RP"
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 90 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	sleep 2
	jrun ed1 "$MPING" -s -i epair101a -t 5 -c 40 -w 60 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 || true
	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true

	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
	if [ "$replies" -ge "$MIN_REPLIES" ]; then
		ok "ED1 -> $GROUP -> ED2, $replies replies"
	else
		fail "only $replies replies, want >= $MIN_REPLIES, see $WORKDIR/sender.log"
	fi

	print "5. pimd installed the route it claims to have"
	if has_mrt r3 "$GROUP"; then
		ok "r3 has $GROUP in its multicast routing table"
	else
		fail "r3 has no $GROUP entry in 'pimctl show mrt'"
	fi
	if has_mrt r1 "$SRC_ADDR"; then
		ok "r1 has an (S,G) for source $SRC_ADDR"
	else
		fail "r1 has no (S,G) for $SRC_ADDR"
	fi

	print "6. The kernel MFC in each vnet agrees with pimd"
	if has_mfc r3 "$GROUP"; then
		ok "r3 kernel has an MFC entry for $GROUP"
	else
		fail "r3 kernel MFC is empty, pimd never pushed the route down"
	fi
	if has_mfc r1 "$GROUP"; then
		ok "r1 kernel has an MFC entry for $GROUP"
	else
		fail "r1 kernel MFC is empty"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in $ROUTERS; do
		dprint "--- $r: pimctl show pim detail ---"
		pimctl "$r" show pim detail 2>&1 | tail -40 || true
	done
	return 1
}

# Issue #251: R1 is the DR for the directly connected source and the RP
# for the groups it sends to, and nobody ever joins them, so the (S,G)
# entries have an empty outgoing interface list and no kernel MFC entry.
# Their only sign of life is the IGMPMSG_NOCACHE upcall the kernel raises
# every UPCALL_EXPIRE (1.5s on FreeBSD), and process_cache_miss() has to
# restart the entry timer from it.  When it does not, age_routes() deletes
# each entry within one TIMER_INTERVAL of its creation and the table
# content is different every time you look at it.
# ssm: IGMPv3 (S,G) membership state on the last hop router.
#
# The reports are generated by test/igmpv3.c rather than by joining the
# group on ED2.  A kernel join answers every query R3 sends afterwards,
# so the membership can never age out while ED2 is on the LAN, and taking
# ED2 off the LAN destroys the epair and R3's vif with it.  Sending one
# report and stopping is the only way to ask "does this membership expire
# when the receiver goes quiet?", which is assertion 4.
check_ssm() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if pimctl "$r" show status >/dev/null 2>&1; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. A report with two sources creates one membership each"
	ssm_report -t allow "$SSM_SRC1" "$SSM_SRC2"
	if wait_for 15 ssm_count_is 2; then
		ok "R3 holds ($SSM_SRC1,$GROUP) and ($SSM_SRC2,$GROUP)"
	else
		fail "R3 holds $(ssm_sources | tr '\n' ' ')instead of both sources"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "3. Blocking one source leaves the other alone"
	ssm_report -t block "$SSM_SRC2"
	if wait_for 15 ssm_count_is 1 && [ "$(ssm_sources)" = "$SSM_SRC1" ]; then
		ok "R3 dropped $SSM_SRC2 and kept $SSM_SRC1"
	else
		fail "block left $(ssm_sources | tr '\n' ' ')behind"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# The regression.  One timer per group, holding whichever source
	# reported last, means the block above cancelled the only timer the
	# group had: the membership then outlives any timeout, because
	# nothing is left to expire it.  A leave for the last source still
	# cleans up, so only a receiver that goes quiet shows this.
	print "4. The surviving membership ages out once the reports stop"
	dprint "waiting up to $((SSM_TIMEOUT * 2))s, the membership timeout is ${SSM_TIMEOUT}s"
	if wait_for $((SSM_TIMEOUT * 2)) ssm_count_is 0; then
		ok "($SSM_SRC1,$GROUP) expired with no report to refresh it"
	else
		fail "($SSM_SRC1,$GROUP) never expired, no timer left after the block"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "5. A report with more sources than pimd keeps is bounded"
	ssm_report -t allow -n $((SSM_MAX_SOURCES + 144)) -b 10.0.1.100
	sleep 2
	if ! pimctl r3 show status >/dev/null 2>&1; then
		fail "pimd stopped answering after a $((SSM_MAX_SOURCES + 144)) source report"
		return 1
	fi

	num=$(ssm_sources | wc -l | tr -d ' ')
	if [ "$num" -ge 1 ] && [ "$num" -le "$SSM_MAX_SOURCES" ]; then
		ok "R3 kept $num sources, at most $SSM_MAX_SOURCES"
	else
		fail "R3 kept $num sources, the list is not bounded"
	fi

	[ "$FAILED" -eq 0 ] || return 1
	return 0
}

# Send one IGMPv3 report for $GROUP from ED2
ssm_report() {
	jrun ed2 "$IGMPV3" -i "$RCV_ADDR" -g "$GROUP" "$@" || \
		die "failed sending an IGMPv3 report from ed2"
}

# Sources R3 holds for $GROUP.  "show igmp" prints one line per (group,
# source) and "ANY" in the source column for an any-source membership, so
# this lists (S,G) memberships only.
ssm_sources() {
	pimctl r3 -t show igmp 2>/dev/null | \
		awk -v grp="$GROUP" '$2 == grp && $3 != "ANY" { print $3 }'
}

# For wait_for(), which needs a command that returns a status
ssm_count_is() {
	[ "$(ssm_sources | wc -l | tr -d ' ')" -eq "$1" ]
}

check_keepalive() {
	print "1. pimd is alive on R1"
	if pimctl r1 show status >/dev/null 2>&1; then
		ok "r1: pimd answers on its pimctl socket"
	else
		fail "r1: pimd not answering, see $WORKDIR/r1.log"
		return 1
	fi

	print "2. R1 elected itself RP for the groups its source sends to"
	if wait_for 90 has_rp r1 10.0.1.1; then
		ok "r1 is the RP (10.0.1.1)"
	else
		fail "r1 never became RP, see $WORKDIR/r1.log"
		return 1
	fi

	print "3. R1 learns all $KEEP_NUM sources"
	if wait_for 60 all_sources_up; then
		ok "r1 has (S,G) entries for $(sources | tr '\n' ' ')"
	else
		fail "r1 only has $(sources | wc -l | tr -d ' ')/$KEEP_NUM (S,G) entries"
		return 1
	fi

	print "4. The sources stay put for ${KEEP_SECONDS}s while they keep sending"
	deadline=$(($(date +%s) + KEEP_SECONDS))
	samples=0
	missing=0
	dead=0
	worst=$KEEP_NUM
	while [ "$(date +%s)" -lt "$deadline" ]; do
		timers=$(source_timers)
		n=$(echo "$timers" | grep -c . || true)
		samples=$((samples + 1))

		if [ "$n" -ne "$KEEP_NUM" ]; then
			missing=$((missing + 1))
			[ "$n" -lt "$worst" ] && worst=$n
		fi

		# An entry whose keepalive timer is 0 is one age_routes()
		# run away from being deleted, however fast the next cache
		# miss brings it back
		if echo "$timers" | awk '$2 == 0 { found = 1 } END { exit !found }'; then
			dead=$((dead + 1))
		fi

		sleep 5
	done

	if [ "$missing" -eq 0 ]; then
		ok "all $KEEP_NUM sources present in every one of $samples samples"
	else
		fail "sources vanished in $missing of $samples samples, down to $worst/$KEEP_NUM"
	fi

	if [ "$dead" -eq 0 ]; then
		ok "every (S,G) kept a running entry timer in all $samples samples"
	else
		fail "(S,G) entry timer was 0, so the entry was being deleted and recreated, in $dead of $samples samples"
	fi

	if [ "$FAILED" -ne 0 ]; then
		dprint "--- r1: pimctl show mrt detail ---"
		pimctl r1 show mrt detail 2>&1 | tail -40 || true
		dprint "--- cache misses logged on r1: $(${SUDO} grep -c "Cache miss" "$WORKDIR/r1.log" 2>/dev/null || echo 0) ---"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	return 1
}

# Issue #243: R3 is the RP and the last hop router at once, and the source
# is remote, behind R1.  R3's (*,G) has the register vif as its incoming
# interface because the RP is itself (set_incoming(), PIM_IIF_RP), R1
# encapsulates the source to it, and the traffic then has to come back out
# of the register vif and down to the directly connected member on
# epair203a.  Every reporter on the issue says it does not: their receivers
# on the RP's own LAN see nothing from the remote source, while the
# opposite direction works, and moving the RP moves the broken direction.
#
# Their RP dumps show the (S,G) for the remote source stuck with the
# register vif as incoming interface, no CACHE flag, and the first hop
# router still registering.  So there are three separate things to check
# and they can fail independently: whether packets arrive at all, whether
# the RP ever leaves the register vif for a native iif, and whether pimd
# pushed anything down to the kernel MFC.
check_rp_lasthop() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if pimctl "$r" show status >/dev/null 2>&1; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. R3 is the RP, and R1 knows where to send its registers"
	if wait_for 90 has_rp r3 "$RPLH_ADDR"; then
		ok "r3 elected itself RP ($RPLH_ADDR)"
	else
		fail "r3 never became RP, see $WORKDIR/r3.log"
		return 1
	fi
	if wait_for 90 has_rp r1 "$RPLH_ADDR"; then
		ok "r1 learned RP $RPLH_ADDR"
	else
		fail "r1 never learned RP $RPLH_ADDR (BSR/cand-RP path)"
		return 1
	fi

	print "3. ED2's membership reaches the RP it is directly attached to"
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 60 has_mrt r3 "$GROUP"; then
		ok "r3 has a ($GROUP) entry for its directly connected member"
	else
		fail "r3 never saw ED2's IGMP report, see $WORKDIR/r3.log"
		kill "$receiver" 2>/dev/null || true
		return 1
	fi

	print "4. Multicast reaches the receiver hanging off the RP itself"
	run_stream_and_sample
	if [ "$replies" -ge "$MIN_RECEIVED" ]; then
		ok "ED1 -> $GROUP -> ED2, $replies of $STREAM_PKTS packets delivered and answered"
	else
		fail "only $replies of $STREAM_PKTS packets reached ED2 ($RCV_ADDR), want >= $MIN_RECEIVED"
	fi

	print "5. The RP builds (S,G) state for the remote source and leaves the register vif"
	if [ -n "$sg_seen" ]; then
		ok "r3 created an ($SRC_ADDR,$GROUP) entry while the stream was running"
	else
		fail "r3 never created an ($SRC_ADDR,$GROUP) entry, it only ever had the (*,G)"
	fi
	if [ -n "$sg_native" ]; then
		ok "r3 ($SRC_ADDR,$GROUP) incoming interface became vif $sg_native, not the register vif"
	else
		fail "r3 ($SRC_ADDR,$GROUP) stayed on the register vif (vif 0), the RP never switched to the SPT"
	fi

	# The RP is supposed to pull the source onto a native path and
	# register-stop R1 within the first packets.  One register per data
	# packet is the encapsulate-forever state of the issue.
	print "6. The RP stops the registers instead of decapsulating every packet"
	if [ "$regs" -lt "$MAX_REGISTERS" ]; then
		ok "r3 decapsulated $regs registers for $STREAM_PKTS packets"
	else
		fail "r3 decapsulated $regs registers for $STREAM_PKTS packets, it never register-stopped r1"
	fi

	print "7. The kernel MFC on the RP agrees with pimd"
	if has_mfc r3 "$SRC_ADDR"; then
		ok "r3 kernel has an MFC entry for $SRC_ADDR"
	else
		fail "r3 kernel MFC has nothing for $SRC_ADDR, pimd never pushed the route down"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in $ROUTERS; do
		dprint "--- $r: pimctl show mrt detail ---"
		pimctl "$r" show mrt detail 2>&1 | tail -40 || true
	done
	dprint "--- r3: netstat -gn ---"
	jrun r3 netstat -gn 2>&1 || true
	dprint "--- registers decapsulated by r3, total: $(registers_seen) ---"
	return 1
}

# The gif-tunnel variant of check_rp_lasthop.  Same RP-is-also-last-hop
# question, but now everything PIM crosses a point-to-point tunnel and R2
# is not a PIM router at all, so the two ends have to find each other with
# nothing but unicast in between.  What is genuinely new here is the
# interface type: config_vifs_from_kernel() takes the IFF_POINTOPOINT
# branch, so uv_rmt_addr comes from ifa_dstaddr and the vif is flagged
# VIFF_POINT_TO_POINT | VIFF_REXMIT_PRUNES, and the hellos, the DR
# election and the RPF answers all have to work off that.
check_gif_tunnel() {
	print "1. pimd is alive on both tunnel endpoints"
	for r in $(pim_routers); do
		if pimctl "$r" show status >/dev/null 2>&1; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. pimd accepted the point-to-point tunnel as a vif"
	for r in $(pim_routers); do
		if has_iface "$r" "$GIF_IF"; then
			ok "$r has $GIF_IF in its interface table"
		else
			fail "$r never built a vif for $GIF_IF, see $WORKDIR/$r.log for an 'Ignoring' line"
		fi
	done
	if took_p2p_branch r1 "$GIF_R1" "$GIF_R3" &&
	   took_p2p_branch r3 "$GIF_R3" "$GIF_R1"; then
		ok "both ends installed $GIF_IF through the IFF_POINTOPOINT branch"
	else
		fail "$GIF_IF came up as an ordinary subnet vif, this scenario is not exercising the tunnel path"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "3. PIM adjacency comes up across the tunnel"
	if wait_for 90 has_neighbor r1 "$GIF_R3"; then
		ok "r1 sees r3 ($GIF_R3) over $GIF_IF"
	else
		fail "r1 never saw r3 over the tunnel, hellos are not crossing $GIF_IF"
	fi
	if wait_for 90 has_neighbor r3 "$GIF_R1"; then
		ok "r3 sees r1 ($GIF_R1) over $GIF_IF"
	else
		fail "r3 never saw r1 over the tunnel"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "4. R3 is the RP, and R1 learns it through the tunnel"
	if wait_for 90 has_rp r3 "$RPLH_ADDR"; then
		ok "r3 elected itself RP ($RPLH_ADDR)"
	else
		fail "r3 never became RP, see $WORKDIR/r3.log"
		return 1
	fi
	if wait_for 90 has_rp r1 "$RPLH_ADDR"; then
		ok "r1 learned RP $RPLH_ADDR over the tunnel"
	else
		fail "r1 never learned RP $RPLH_ADDR, bootstrap is not crossing $GIF_IF"
		return 1
	fi

	print "5. ED2's membership reaches the RP it is directly attached to"
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 60 has_mrt r3 "$GROUP"; then
		ok "r3 has a ($GROUP) entry for its directly connected member"
	else
		fail "r3 never saw ED2's IGMP report, see $WORKDIR/r3.log"
		kill "$receiver" 2>/dev/null || true
		return 1
	fi

	print "6. Multicast crosses the tunnel to the receiver on the RP"
	run_stream_and_sample
	if [ "$replies" -ge "$MIN_RECEIVED" ]; then
		ok "ED1 -> $GROUP -> ED2 over $GIF_IF, $replies of $STREAM_PKTS delivered and answered"
	else
		fail "only $replies of $STREAM_PKTS packets reached ED2 ($RCV_ADDR) through the tunnel"
	fi

	print "7. The RP builds (S,G) state and leaves the register vif"
	if [ -n "$sg_seen" ]; then
		ok "r3 created an ($SRC_ADDR,$GROUP) entry while the stream was running"
	else
		fail "r3 never created an ($SRC_ADDR,$GROUP) entry, it only ever had the (*,G)"
	fi
	if [ -n "$sg_native" ]; then
		ok "r3 ($SRC_ADDR,$GROUP) incoming interface became vif $sg_native, not the register vif"
	else
		fail "r3 ($SRC_ADDR,$GROUP) stayed on the register vif (vif 0), the RP never switched to the SPT"
	fi

	print "8. The RP stops the registers instead of decapsulating every packet"
	if [ "$regs" -lt "$MAX_REGISTERS" ]; then
		ok "r3 decapsulated $regs registers for $STREAM_PKTS packets"
	else
		fail "r3 decapsulated $regs registers for $STREAM_PKTS packets, it never register-stopped r1"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	# show compat prints the vif table with its Subnet column, which is
	# the format the issue reporters pasted and the place a mishandled
	# point-to-point netmask would show up
	for r in $(pim_routers); do
		dprint "--- $r: pimctl show compat detail ---"
		pimctl "$r" show compat detail 2>&1 | head -30 || true
		dprint "--- $r: ifconfig $GIF_IF ---"
		jrun "$r" ifconfig "$GIF_IF" 2>&1 | head -4 || true
	done
	dprint "--- registers decapsulated by r3, total: $(registers_seen) ---"
	return 1
}

# gif-tunnel again, but with the RP configured statically on both ends,
# the way every pimd.conf quoted in #243 is written.  See write_configs()
# for why that is a different code path and not just a different way of
# reaching the same state: my_cand_rp_address stays 0.0.0.0 on a static
# RP, so the router that *is* the RP answers "no" to every internal test
# of whether it is.
check_gif_staticrp() {
	print "1. pimd is alive on both tunnel endpoints"
	for r in $(pim_routers); do
		if pimctl "$r" show status >/dev/null 2>&1; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. Both ends took the static RP from pimd.conf"
	for r in $(pim_routers); do
		if wait_for 30 has_static_rp "$r" "$RPLH_ADDR"; then
			ok "$r has $RPLH_ADDR as a static RP for $GROUP"
		else
			fail "$r did not accept 'rp-address $RPLH_ADDR 224.0.0.0/16', see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "3. PIM adjacency comes up across the tunnel"
	if wait_for 90 has_neighbor r1 "$GIF_R3"; then
		ok "r1 sees r3 ($GIF_R3) over $GIF_IF"
	else
		fail "r1 never saw r3 over the tunnel"
	fi
	if wait_for 90 has_neighbor r3 "$GIF_R1"; then
		ok "r3 sees r1 ($GIF_R1) over $GIF_IF"
	else
		fail "r3 never saw r1 over the tunnel"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "4. ED2's membership reaches the RP it is directly attached to"
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 60 has_mrt r3 "$GROUP"; then
		ok "r3 has a ($GROUP) entry for its directly connected member"
	else
		fail "r3 never saw ED2's IGMP report, see $WORKDIR/r3.log"
		kill "$receiver" 2>/dev/null || true
		return 1
	fi

	# A static RP is known from the moment pimd parses pimd.conf, so
	# this scenario reaches its first four assertions in seconds, where
	# the elected-RP one spends up to 90s waiting for bootstrap.  Left
	# alone, the stream would then start much earlier in the lab's life
	# and measure a slice of PIM convergence that gif-tunnel has already
	# sat through, and the two delivery counts would not be comparable.
	print "5. Letting PIM settle so the delivery count means the same thing as gif-tunnel's"
	sleep "$SETTLE"

	print "6. Multicast crosses the tunnel to the receiver on the RP"
	run_stream_and_sample
	if [ "$replies" -ge "$MIN_RECEIVED" ]; then
		ok "ED1 -> $GROUP -> ED2 over $GIF_IF, $replies of $STREAM_PKTS delivered and answered"
	else
		fail "only $replies of $STREAM_PKTS packets reached ED2 ($RCV_ADDR) through the tunnel"
	fi

	print "7. The RP builds (S,G) state and leaves the register vif"
	if [ -n "$sg_seen" ]; then
		ok "r3 created an ($SRC_ADDR,$GROUP) entry while the stream was running"
	else
		fail "r3 never created an ($SRC_ADDR,$GROUP) entry, it only ever had the (*,G)"
	fi
	if [ -n "$sg_native" ]; then
		ok "r3 ($SRC_ADDR,$GROUP) incoming interface became vif $sg_native, not the register vif"
	else
		fail "r3 ($SRC_ADDR,$GROUP) stayed on the register vif (vif 0), the RP never switched to the SPT"
	fi

	print "8. The RP stops the registers instead of decapsulating every packet"
	if [ "$regs" -lt "$MAX_REGISTERS" ]; then
		ok "r3 decapsulated $regs registers for $STREAM_PKTS packets"
	else
		fail "r3 decapsulated $regs registers for $STREAM_PKTS packets, it never register-stopped r1"
	fi

	# The assertion this scenario exists for.  R3 is the RP for $GROUP
	# and the DR for $RCV_ADDR's subnet, so it must never put the
	# register vif in that source's oif list: there is nobody to
	# register to but itself.  process_cache_miss() decides that with
	# "group->rpaddr != my_cand_rp_address" (src/route.c), which a
	# static RP can never satisfy.
	print "9. The RP does not encapsulate its own directly connected source to itself"
	if [ -z "$selfreg" ]; then
		ok "r3 kept the register vif out of the oifs for $RCV_ADDR"
	else
		fail "r3 put the register vif in the oifs for its own source $RCV_ADDR, it is registering to itself"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in $(pim_routers); do
		dprint "--- $r: pimctl show compat detail ---"
		pimctl "$r" show compat detail 2>&1 | head -30 || true
	done
	dprint "--- r3: pimctl show mrt detail ---"
	pimctl r3 show mrt detail 2>&1 | head -40 || true
	dprint "--- registers decapsulated by r3, total: $(registers_seen) ---"
	return 1
}

# The shared segment scenario.  Everything up to assertion 5 is the rpt
# scenario with the right hand links rebuilt as bridges; from 6 on it is the
# part no point-to-point link can reach, where three routers have to agree
# on who speaks for a LAN they all sit on.
check_shared_lan() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if pimctl "$r" show status >/dev/null 2>&1; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. Every router on a bridged segment sees every other one"
	for pair in "r2 10.0.23.3" "r2 10.0.23.4" \
		    "r3 10.0.23.2" "r3 10.0.23.4" \
		    "r4 10.0.23.2" "r4 10.0.23.3"; do
		# shellcheck disable=SC2086
		set -- $pair
		if wait_for 60 has_neighbor "$1" "$2"; then
			ok "$1 sees $2 on the upstream segment"
		else
			fail "$1 never saw $2, PIM hello is not crossing $BR_UPSTREAM"
		fi
	done
	for pair in "r3 $SL_DR_ADDR" "r3 $SL_QUERIER_ADDR" \
		    "r4 $SL_R3_ADDR" "r4 $SL_QUERIER_ADDR" \
		    "r5 $SL_R3_ADDR" "r5 $SL_DR_ADDR"; do
		# shellcheck disable=SC2086
		set -- $pair
		if wait_for 60 has_neighbor "$1" "$2"; then
			ok "$1 sees $2 on the shared LAN"
		else
			fail "$1 never saw $2, PIM hello is not crossing $BR_RECEIVER"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "3. The DR election on the shared LAN takes the highest address"
	dr3=$(iface_dr r3 "$SL_R3_IF")
	dr4=$(iface_dr r4 "$SL_R4_IF")
	dr5=$(iface_dr r5 epair503b)
	if [ "$dr3" = "$SL_DR_ADDR" ] && [ "$dr4" = "$SL_DR_ADDR" ] &&
	   [ "$dr5" = "$SL_DR_ADDR" ]; then
		ok "r3, r4 and r5 all call $SL_DR_ADDR (r4) the DR"
	else
		fail "DR disagreement: r3 '$dr3', r4 '$dr4', r5 '$dr5', all should say $SL_DR_ADDR"
	fi

	# Two elections over the same wire, deliberately won by different
	# routers: PIM takes the highest address, IGMP the lowest.
	print "4. The IGMP querier election takes the lowest, i.e. another router"
	q3=$(iface_querier r3 "$SL_R3_IF")
	q4=$(iface_querier r4 "$SL_R4_IF")
	q5=$(iface_querier r5 epair503b)
	if [ "$q5" = "Local" ] && [ "$q3" = "$SL_QUERIER_ADDR" ] &&
	   [ "$q4" = "$SL_QUERIER_ADDR" ]; then
		ok "r5 ($SL_QUERIER_ADDR) is the querier, r3 and r4 agree"
	else
		fail "querier disagreement: r5 '$q5' (want Local), r3 '$q3', r4 '$q4' (want $SL_QUERIER_ADDR)"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "5. The RP set is distributed by the bootstrap router"
	for r in $ROUTERS; do
		if wait_for 90 has_rp "$r" "$RP_ADDR"; then
			ok "$r learned RP $RP_ADDR"
		else
			fail "$r never learned RP $RP_ADDR (BSR/cand-RP path)"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	# ED3 joins first, and on its own port, so this window has exactly one
	# reason for anyone to forward onto the LAN: an IGMP report.  pimd
	# gives it to the DR alone.  add_leaf() (src/route.c) looks the group
	# up with DONT_CREATE unless VIFF_DR is set, on the grounds that "if a
	# non-DR last-hop router has not received a PIM Join, it should not
	# create a PIM state, otherwise later this state may incorrectly
	# trigger PIM joins" - a deliberate deviation, and the reason this
	# scenario needs a downstream router to get its second forwarder.
	print "6. An IGMP report on the LAN is taken by the DR and by nobody else"
	jrun ed3 "$MPING" -r -i epair603b -p "$SL_JOIN_PORT" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/joiner.log" 2>&1 &
	joiner=$!
	if wait_for 60 has_mrt r4 "$GROUP"; then
		ok "r4, the DR, created a ($GROUP) entry for ED3's report"
	else
		fail "r4 never saw ED3's IGMP report, see $WORKDIR/r4.log"
		kill "$joiner" 2>/dev/null || true
		return 1
	fi
	if has_mrt r3 "$GROUP"; then
		fail "r3 is not the DR but created a ($GROUP) entry from the report alone"
	else
		ok "r3, not the DR, created nothing from the same report"
	fi

	# The other way onto a LAN: R5 wants the group for ED2 and its RPF
	# neighbour is R3, so its Join names R3, and R3 is the one router on
	# the LAN that may act on it.
	print "7. A downstream Join gives the non-DR an oif on the same LAN"
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 90 joined_on r3 "$SL_R3_IF" "$GROUP"; then
		ok "r3 joined $GROUP towards the LAN on r5's behalf"
	else
		fail "r3 never took r5's Join, see $WORKDIR/r3.log"
		kill "$joiner" "$receiver" 2>/dev/null || true
		return 1
	fi

	print "8. Multicast reaches the receiver at the far end of the tree"
	run_stream_and_sample_shared
	kill "$joiner" 2>/dev/null || true
	if [ "$replies" -ge "$MIN_RECEIVED" ]; then
		ok "ED1 -> $GROUP -> ED2, $replies replies for $STREAM_PKTS packets"
	else
		fail "only $replies replies for $STREAM_PKTS packets, want >= $MIN_RECEIVED"
	fi

	# The assertion this scenario exists for.  R3 is the RP for $GROUP
	# and the DR for $RCV_ADDR's subnet, so it must never put the
	# register vif in that source's oif list: there is nobody to
	# register to but itself.  process_cache_miss() decides that with
	# "group->rpaddr != my_cand_rp_address" (src/route.c), which a
	# static RP can never satisfy.
	print "9. The RP does not encapsulate its own directly connected source to itself"
	if [ -z "$selfreg" ]; then
		ok "r3 kept the register vif out of the oifs for $RCV_ADDR"
	else
		fail "r3 put the register vif in the oifs for its own source $RCV_ADDR, it is registering to itself"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in $(pim_routers); do
		dprint "--- $r: pimctl show compat detail ---"
		pimctl "$r" show compat detail 2>&1 | head -30 || true
	done
	dprint "--- r3: pimctl show mrt detail ---"
	pimctl r3 show mrt detail 2>&1 | head -40 || true
	dprint "--- registers decapsulated by r3, total: $(registers_seen) ---"
	return 1
}

# The shared segment scenario.  Everything up to assertion 5 is the rpt
# scenario with the right hand links rebuilt as bridges; from 6 on it is the
# part no point-to-point link can reach, where three routers have to agree
# on who speaks for a LAN they all sit on.
check_shared_lan() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if pimctl "$r" show status >/dev/null 2>&1; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. Every router on a bridged segment sees every other one"
	for pair in "r2 10.0.23.3" "r2 10.0.23.4" \
		    "r3 10.0.23.2" "r3 10.0.23.4" \
		    "r4 10.0.23.2" "r4 10.0.23.3"; do
		# shellcheck disable=SC2086
		set -- $pair
		if wait_for 60 has_neighbor "$1" "$2"; then
			ok "$1 sees $2 on the upstream segment"
		else
			fail "$1 never saw $2, PIM hello is not crossing $BR_UPSTREAM"
		fi
	done
	for pair in "r3 $SL_DR_ADDR" "r3 $SL_QUERIER_ADDR" \
		    "r4 $SL_R3_ADDR" "r4 $SL_QUERIER_ADDR" \
		    "r5 $SL_R3_ADDR" "r5 $SL_DR_ADDR"; do
		# shellcheck disable=SC2086
		set -- $pair
		if wait_for 60 has_neighbor "$1" "$2"; then
			ok "$1 sees $2 on the shared LAN"
		else
			fail "$1 never saw $2, PIM hello is not crossing $BR_RECEIVER"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "3. The DR election on the shared LAN takes the highest address"
	dr3=$(iface_dr r3 "$SL_R3_IF")
	dr4=$(iface_dr r4 "$SL_R4_IF")
	dr5=$(iface_dr r5 epair503b)
	if [ "$dr3" = "$SL_DR_ADDR" ] && [ "$dr4" = "$SL_DR_ADDR" ] &&
	   [ "$dr5" = "$SL_DR_ADDR" ]; then
		ok "r3, r4 and r5 all call $SL_DR_ADDR (r4) the DR"
	else
		fail "DR disagreement: r3 '$dr3', r4 '$dr4', r5 '$dr5', all should say $SL_DR_ADDR"
	fi

	# Two elections over the same wire, deliberately won by different
	# routers: PIM takes the highest address, IGMP the lowest.
	print "4. The IGMP querier election takes the lowest, i.e. another router"
	q3=$(iface_querier r3 "$SL_R3_IF")
	q4=$(iface_querier r4 "$SL_R4_IF")
	q5=$(iface_querier r5 epair503b)
	if [ "$q5" = "Local" ] && [ "$q3" = "$SL_QUERIER_ADDR" ] &&
	   [ "$q4" = "$SL_QUERIER_ADDR" ]; then
		ok "r5 ($SL_QUERIER_ADDR) is the querier, r3 and r4 agree"
	else
		fail "querier disagreement: r5 '$q5' (want Local), r3 '$q3', r4 '$q4' (want $SL_QUERIER_ADDR)"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "5. The RP set is distributed by the bootstrap router"
	for r in $ROUTERS; do
		if wait_for 90 has_rp "$r" "$RP_ADDR"; then
			ok "$r learned RP $RP_ADDR"
		else
			fail "$r never learned RP $RP_ADDR (BSR/cand-RP path)"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	# ED3 joins first, and on its own port, so this window has exactly one
	# reason for anyone to forward onto the LAN: an IGMP report.  pimd
	# gives it to the DR alone.  add_leaf() (src/route.c) looks the group
	# up with DONT_CREATE unless VIFF_DR is set, on the grounds that "if a
	# non-DR last-hop router has not received a PIM Join, it should not
	# create a PIM state, otherwise later this state may incorrectly
	# trigger PIM joins" - a deliberate deviation, and the reason this
	# scenario needs a downstream router to get its second forwarder.
	print "6. An IGMP report on the LAN is taken by the DR and by nobody else"
	jrun ed3 "$MPING" -r -i epair603b -p "$SL_JOIN_PORT" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/joiner.log" 2>&1 &
	joiner=$!
	if wait_for 60 has_mrt r4 "$GROUP"; then
		ok "r4, the DR, created a ($GROUP) entry for ED3's report"
	else
		fail "r4 never saw ED3's IGMP report, see $WORKDIR/r4.log"
		kill "$joiner" 2>/dev/null || true
		return 1
	fi
	if has_mrt r3 "$GROUP"; then
		fail "r3 is not the DR but created a ($GROUP) entry from the report alone"
	else
		ok "r3, not the DR, created nothing from the same report"
	fi

	# The other way onto a LAN: R5 wants the group for ED2 and its RPF
	# neighbour is R3, so its Join names R3, and R3 is the one router on
	# the LAN that may act on it.
	print "7. A downstream Join gives the non-DR an oif on the same LAN"
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 90 joined_on r3 "$SL_R3_IF" "$GROUP"; then
		ok "r3 joined $GROUP towards the LAN on r5's behalf"
	else
		fail "r3 never took r5's Join, see $WORKDIR/r3.log"
		kill "$joiner" "$receiver" 2>/dev/null || true
		return 1
	fi

	print "8. Multicast reaches the receiver at the far end of the tree"
	run_stream_and_sample_shared
	kill "$joiner" 2>/dev/null || true
	if [ "$replies" -ge "$MIN_RECEIVED" ]; then
		ok "ED1 -> $GROUP -> ED2, $replies replies for $STREAM_PKTS packets"
	else
		fail "only $replies replies for $STREAM_PKTS packets, want >= $MIN_RECEIVED"
	fi

	# The assertion these scenarios exist for.  Both routers put the group
	# on the LAN, so each of them receives the other's copy on an
	# interface that is not its own iif, the kernel raises IGMPMSG_WRONGVIF
	# for it (ip_mroute.c, with the assert upcalls pimd turns on through
	# MRT_PIM), and the loser of the election that follows has to take its
	# oif back out.  The election itself is not in the default debug set;
	# "pimctl -u $WORKDIR/r3.sock debug asserts" on a running lab logs the
	# Send/Received PIM ASSERT pair that produced this state.
	#
	# Who should win differs between the two scenarios, and that is the
	# reason shared-lan-spt exists.  RFC 7761 4.6.1 compares assert
	# metrics field by field, rpt_bit_flag first, and my_assert_metric()
	# (p.93) only returns the SPT metric, with that flag clear, when
	# CouldAssert(S,G,I) holds - which requires SPTbit(S,G) == TRUE
	# (p.75).  A router forwarding a group it only has (*,G) state for
	# must therefore assert with the flag set, and lose to one that has
	# (S,G) state, whatever the addresses are.
	#
	# In shared-lan neither contender has (S,G) state of its own, both
	# assert as RPT forwarders, and the address decides: R4 wins.
	#
	# In shared-lan-spt R5's switch gives R3 real (S,G) state while R4
	# still has only ED3's (*,G) leaf, so R3 must win with the *lower*
	# address.  pimd does not do that today.  It takes the RPT bit
	# straight from MRTF_RP on whichever entry it is forwarding off
	# (send_pim_assert(), src/pim_proto.c), and MRTF_RP is only ever set
	# from an explicit (S,G,rpt) Join/Prune or when an entry's iif changes
	# to point at the RP (src/route.c, src/mrt.c) - never on the (S,G) a
	# cache miss builds under a (*,G).  So R4 asserts as though it were on
	# the shortest path tree too, both metrics tie, and the address hands
	# it a win the spec does not.
	if [ "$SCENARIO" = shared-lan-spt ]; then
		print "9. The assert winner is the router with the better tree"
		if [ -z "$sg3" ]; then
			fail "r3 never got (S,G) state from r5, the election below cannot be read; r5 never switched, see $WORKDIR/r5.log"
		elif [ -n "$fwd3" ] && [ -z "$fwd4" ]; then
			ok "r3 won with the lower address, off its (S,G): pimd now sets the RPT bit as RFC 7761 4.6.1 requires, this can stop being a known deviation"
		elif [ -n "$fwd4" ] && [ -z "$fwd3" ]; then
			xfail "r4 ($SL_DR_ADDR) won on the address; per RFC 7761 4.6.1 r3 has (S,G) state and r4 only (*,G), so r4 must assert with the RPT bit set and lose"
		elif [ -n "$fwd3" ] && [ -n "$fwd4" ]; then
			fail "both r3 and r4 still forward $GROUP onto the LAN, no assert settled it"
		else
			fail "neither r3 nor r4 forwards $GROUP onto the LAN"
		fi
	else
		print "9. The duplicate on the LAN is settled by a PIM assert"
		if [ -n "$fwd4" ] && [ -z "$fwd3" ]; then
			ok "only r4 ($SL_DR_ADDR) still forwards $GROUP onto the LAN, it has the higher address"
		elif [ -n "$fwd3" ] && [ -n "$fwd4" ]; then
			fail "both r3 and r4 still forward $GROUP onto the LAN, no assert settled it"
		elif [ -n "$fwd3" ]; then
			fail "r3 ($SL_R3_ADDR) won the assert, r4 has the higher address and should have"
		else
			fail "neither r3 nor r4 forwards $GROUP onto the LAN"
		fi
		if [ -n "$ast3" ] && [ -z "$ast4" ]; then
			ok "r3 has the LAN in its asserted oifs, r4 does not"
		else
			fail "asserted oifs are wrong: r3 '${ast3:-none}', r4 '${ast4:-none}'"
		fi
	fi

	print "10. Only the DR registers the source that sits on the shared LAN"
	if [ -z "$reg3" ]; then
		ok "r3 kept the register vif out of the oifs for $SL_ED3_ADDR"
	else
		fail "r3 is not the DR for $SL_ED3_ADDR but registered it anyway"
	fi

	# Whoever won it, the winner is the one that has to hold the kernel
	# state: asserting is only half of it, the forwarding has to follow.
	winner=r4
	[ -n "$fwd3" ] && winner=r3
	print "11. The kernel MFC on the assert winner agrees with pimd"
	if has_mfc "$winner" "$GROUP"; then
		ok "$winner kernel has an MFC entry for $GROUP"
	else
		fail "$winner won the assert but its kernel MFC is empty, pimd never pushed the route down"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		if [ "$XFAILED" -gt 0 ]; then
			print "RESULT: PASS ($XFAILED known deviation(s), see above)"
		else
			print "RESULT: PASS"
		fi
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in r3 r4 r5; do
		dprint "--- $r: pimctl show interface ---"
		pimctl "$r" show interface 2>&1 || true
		dprint "--- $r: pimctl show igmp ---"
		pimctl "$r" show igmp 2>&1 || true
		dprint "--- $r: pimctl show mrt detail ---"
		pimctl "$r" show mrt detail 2>&1 | head -40 || true
		dprint "--- $r: netstat -gn ---"
		jrun "$r" netstat -gn 2>&1 || true
	done
	return 1
}

stop() {
	for r in $SHARED_ROUTERS; do
		[ -f "$WORKDIR/$r.pid" ] && \
			${SUDO} pkill -F "$WORKDIR/$r.pid" 2>/dev/null || true
	done
	${SUDO} pkill -f "$PIMD -i" 2>/dev/null || true
	${SUDO} pkill -f "$MPING" 2>/dev/null || true
	${SUDO} pkill -f "$MSEND" 2>/dev/null || true

	for box in $ALL_BOXES; do
		destroy_box "$box"
	done

	# Jails can linger in the dying state and hold their interfaces
	sleep 1
	for e in $ALL_EPAIRS; do
		for end in a b; do
			${SUDO} ifconfig "$e$end" destroy 2>/dev/null || true
		done
		${SUDO} ifconfig "$e" destroy 2>/dev/null || true
	done

	for br in $BR_UPSTREAM $BR_RECEIVER; do
		${SUDO} ifconfig "$br" destroy 2>/dev/null || true
	done

	restore_mcast_loop
	${SUDO} rm -rf "$WORKDIR"
}

run_one() {
	rc=0
	start
	check || rc=$?
	if [ "$rc" -ne 0 ]; then
		# stop() wipes the work directory, keep what failed
		saved="$WORKDIR.$SCENARIO.failed"
		${SUDO} rm -rf "$saved"
		${SUDO} cp -a "$WORKDIR" "$saved" 2>/dev/null || true
		echo "pimd logs and traffic captures kept in $saved"
	fi
	stop
	return $rc
}

run() {
	rc=0

	if [ "${1:-}" = all ]; then
		for s in rpt keepalive rp-lasthop gif-tunnel gif-tunnel-staticrp \
			 shared-lan shared-lan-spt ssm; do
			set_scenario "$s"
			print "===== scenario: $s ====="
			run_one || rc=$?
		done
		exit $rc
	fi

	set_scenario "${1:-}"
	run_one || rc=$?
	exit $rc
}

if [ $# -eq 0 ]; then
	usage
	exit 2
fi

cmd=$1
shift
case $cmd in
start|check) set_scenario "${1:-}"; $cmd ;;
run)         run "${1:-}" ;;
stop)        stop ;;
*)           usage; exit 2 ;;
esac
