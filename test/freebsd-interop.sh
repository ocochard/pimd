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
# Which is also why this is not another scenario in freebsd-lab.sh: that
# script needs nothing but jails, and this one needs a 4G VM image, bhyve
# and a vendor OS.  The two labs use different jail, epair and bridge names
# and can be built side by side, but not run at the same time: they share
# net.inet.ip.mcast.loop and the 10.0.0.0/8 addresses.
#
# The VM is driven by veos-bhyve.sh (see $VEOS_SH), which boots the vEOS
# image under bhyve, writes the startup-config this script generates onto
# the guest flash before boot, and exposes eAPI.  Assertions about what the
# Arista believes are read over eAPI, so they are the switch's own view of
# the exchange, not an inference from pimd's logs.
#
# Requirements: root, VIMAGE, ip_mroute.ko, if_bridge.ko, bhyve with a
# vEOS-lab image, python3 (eAPI is JSON), and a built pimd.
#
# Usage: freebsd-interop.sh start|check|run [arista-rp|pimd-rp] | run all | stop

SUDO=${SUDO:-sudo}

PIMD_SRC=${PIMD_SRC:-$(cd "$(dirname "$0")/.." && pwd)}
WORKDIR=${WORKDIR:-/tmp/pimd-interop}

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
VEOS_VM=${VEOS_VM:-veos}
VEOS_QCOW=${VEOS_QCOW:-$HOME/vEOS64-lab-4.36.1F.qcow2}

SCENARIO=${SCENARIO:-arista-rp}
SCENARIOS="arista-rp pimd-rp"

# Jails.  A prefix of their own so this lab and freebsd-lab.sh can be built
# in the same tree without either one destroying the other's boxes.  ED4
# only exists in pimd-rp, where the Arista needs a LAN of its own to be the
# first and last hop router for.
DEFAULT_BOXES="ed1 r1 r3 ed2"
REVERSED_BOXES="ed1 r1 r3 ed2 ed4"
BOXES=$DEFAULT_BOXES
ROUTERS="r1 r3"

# Host bridges: the PIM links the Arista sits on, plus the management
# segment eAPI is reached over.
BR12=bridge812
BR23=bridge823
BR4=bridge804
BR_MGMT=bridge800

# bhyve taps, in PCI order.  The first NIC a vEOS sees is Management1, the
# ones after it are Ethernet1, Ethernet2, ...  All four are always plugged
# in, because the guest numbers its interfaces by PCI slot and Ethernet3
# would move if the list changed between scenarios; only pimd-rp bridges
# the last one to anything.
TAP_MGMT=tap800
TAP_ET1=tap812
TAP_ET2=tap823
TAP_ET3=tap804

# epairs.  The "b" end goes into a jail; for the bridged links the "a" end
# stays on the host and joins the bridge.
DEFAULT_EPAIRS="epair801 epair812 epair823 epair803"
REVERSED_EPAIRS="$DEFAULT_EPAIRS epair804"
EPAIRS=$DEFAULT_EPAIRS

ED1_IF=epair801a
ED2_IF=epair803b
ED4_IF=epair804b

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

MGMT_HOST=172.20.0.1
MGMT_VEOS=172.20.0.2

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
ok()   { printf "  \033[32mok\033[0m    %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; FAILED=$((FAILED + 1)); }

usage() {
	echo "usage: $0 start|check|run [arista-rp|pimd-rp] | run all | stop"
}

set_scenario() {
	case ${1:-$SCENARIO} in
	arista-rp|pimd-rp) SCENARIO=${1:-$SCENARIO} ;;
	*) usage; exit 2 ;;
	esac

	# Read by everything that walks the topology, so a scenario left
	# behind by a previous "run all" cannot leak into the next one.
	if [ "$SCENARIO" = pimd-rp ]; then
		BOXES=$REVERSED_BOXES
		EPAIRS=$REVERSED_EPAIRS
		RP_ADDR=$PIMD_RP_ADDR
	else
		BOXES=$DEFAULT_BOXES
		EPAIRS=$DEFAULT_EPAIRS
		RP_ADDR=$ARISTA_RP_ADDR
	fi
}

# --- boxes ------------------------------------------------------------

jname() { echo "pimx_$1"; }
jrun() { j=$1; shift; ${SUDO} jexec "$(jname "$j")" "$@"; }
pimctl() { j=$1; shift; jrun "$j" "$PIMCTL" -u "$WORKDIR/$j.sock" "$@"; }

ifaces() {
	case $1 in
	ed1) echo "epair801a" ;;
	r1)  echo "epair801b epair812b" ;;
	r3)  echo "epair823b epair803a" ;;
	ed2) echo "epair803b" ;;
	ed4) echo "epair804b" ;;
	esac
}

addrs() {
	case $1 in
	ed1) echo "epair801a 10.0.1.10/24" ;;
	r1)  echo "epair801b 10.0.1.1/24 epair812b 10.0.12.1/24" ;;
	r3)  echo "epair823b 10.0.23.3/24 epair803a 10.0.3.1/24" ;;
	ed2) echo "epair803b 10.0.3.10/24" ;;
	ed4) echo "epair804b $ED4_ADDR/24" ;;
	esac
}

# Static unicast routes, "<destination> <gateway>" pairs.  pimd needs a
# unicast RPF answer for the source and for the RP, and the Arista needs one
# for both edge LANs; its own are in its startup-config.
routes() {
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
	[ -f "$VEOS_QCOW" ] || \
		die "$VEOS_QCOW not found, set VEOS_QCOW to the vEOS-lab image"
	command -v python3 >/dev/null 2>&1 || \
		die "python3 not found, it is what talks JSON to eAPI"
	${SUDO} kldload -n ip_mroute 2>/dev/null || \
		die "cannot load ip_mroute.ko, kernel has no multicast routing"
	${SUDO} kldload -n if_bridge 2>/dev/null || \
		die "cannot load if_bridge.ko, needed for the two PIM links"
	${SUDO} kldload -n vmm nmdm 2>/dev/null || \
		die "cannot load vmm.ko, bhyve is not available"

	if ${SUDO} jls -j pimd_r1 jid >/dev/null 2>&1; then
		die "freebsd-lab.sh is running, the two labs share addresses"
	fi
}

# net.inet.ip.mcast.loop must be 0 for any PIM router on FreeBSD; see the
# long comment on the same sysctl in freebsd-lab.sh.  It is a plain global,
# not VNET-ized, so it has to be changed on the host and restored by stop.
MCAST_LOOP_SAVED="$WORKDIR/mcast_loop.saved"

disable_mcast_loop() {
	sysctl -n net.inet.ip.mcast.loop > "$MCAST_LOOP_SAVED"
	${SUDO} sysctl -q net.inet.ip.mcast.loop=0
}

restore_mcast_loop() {
	[ -f "$MCAST_LOOP_SAVED" ] || return 0
	${SUDO} sysctl -q net.inet.ip.mcast.loop="$(cat "$MCAST_LOOP_SAVED")"
	rm -f "$MCAST_LOOP_SAVED"
}

# --- configuration ----------------------------------------------------

write_configs() {
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
		bsr-candidate epair812b priority $PIMD_BSR_PRIORITY interval 10
		rp-candidate epair812b priority 20 interval 10
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

	# eAPI is JSON-RPC over HTTP and there is no JSON in base, so the one
	# piece of python in this lab lives here.  It prints the text output
	# of each command, which is what the assertions grep.
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

# Run one or more EOS commands and print their text output.  Every command
# runs from enable mode, which is where all the show commands live.
eos() {
	python3 "$EAPI" "http://$MGMT_VEOS/command-api" \
		"$EAPI_USER" "$EAPI_PASS" enable "$@"
}

# --- topology ---------------------------------------------------------

create_lans() {
	bridges="$BR12 $BR23 $BR_MGMT"
	bridged_epairs="epair812 epair823"
	if [ "$SCENARIO" = pimd-rp ]; then
		bridges="$bridges $BR4"
		bridged_epairs="$bridged_epairs epair804"
	fi

	for br in $bridges; do
		if ifconfig "$br" >/dev/null 2>&1; then
			die "$br already exists, it is not ours to reuse"
		fi
		${SUDO} ifconfig bridge create name "$br" group pimx up >/dev/null
	done

	# The management segment is the only one the host has an address on:
	# eAPI has to be reachable from where the assertions run.
	${SUDO} ifconfig "$BR_MGMT" inet "$MGMT_HOST/24" alias

	# The host ends of the PIM links.  Their peers are in the jails.
	for e in $bridged_epairs; do
		${SUDO} ifconfig "$e" create group pimx >/dev/null
		${SUDO} ifconfig "${e}a" up
	done
	${SUDO} ifconfig "$BR12" addm epair812a
	${SUDO} ifconfig "$BR23" addm epair823a
	[ "$SCENARIO" = pimd-rp ] && ${SUDO} ifconfig "$BR4" addm epair804a

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
			${SUDO} ifconfig "${i%a}" create group pimx >/dev/null ;;
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
	et3=$TAP_ET3
	[ "$SCENARIO" = pimd-rp ] && et3="$TAP_ET3:$BR4"

	${SUDO} "$VEOS_SH" -q "$VEOS_QCOW" -n "$VEOS_VM" \
		-t "$TAP_MGMT:$BR_MGMT" -t "$TAP_ET1:$BR12" \
		-t "$TAP_ET2:$BR23" -t "$et3" \
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
		# shellcheck disable=SC2086
		${SUDO} daemon -f -p "$WORKDIR/$r.daemon.pid" \
			-o "$WORKDIR/$r.log" \
			jexec "$(jname "$r")" "$PIMD" -i "$r" -n $DEBUG \
			-f "$WORKDIR/$r.conf" \
			-p "$WORKDIR/$r.pid" \
			-u "$WORKDIR/$r.sock"
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
	for box in $REVERSED_BOXES; do
		destroy_box "$box"
	done

	# An epair that was moved into a jail comes back to the host when the
	# jail dies, but not to the group it was created in: moving an
	# interface between vnets drops its groups.  So the epairs have to be
	# destroyed by name rather than by group, and destroying the "a" end
	# takes the "b" end with it.  The bridges never left the host, but
	# naming them too keeps the teardown in one place.
	for e in $REVERSED_EPAIRS; do
		${SUDO} ifconfig "${e}a" destroy 2>/dev/null || true
	done
	for br in $BR12 $BR23 $BR4 $BR_MGMT; do
		${SUDO} ifconfig "$br" destroy 2>/dev/null || true
	done

	# Anything else this lab created and did not hand to a jail
	for i in $(ifconfig -g pimx 2>/dev/null); do
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

	if wait_for 90 joined_on r1 epair812b "$GROUP"; then
		ok "R1 has epair812b in the oifs of (*, $GROUP)"
	else
		fail "R1 never added epair812b to (*, $GROUP) from the Arista's Join"
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

check() {
	jls -j "$(jname r1)" jid >/dev/null 2>&1 || die "lab is not running, run '$0 start'"
	FAILED=0

	if [ "$SCENARIO" = pimd-rp ]; then
		check_pimd_rp
		return $?
	fi

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
	if wait_for 60 pimd_dr_is r1 epair812b 10.0.12.2; then
		ok "R1 made the Arista DR on 10.0.12.0/24"
	else
		fail "R1 says the DR on 10.0.12.0/24 is '$(pimd_dr r1 epair812b)', expected 10.0.12.2"
	fi
	if wait_for 60 eos_dr_is Ethernet1 10.0.12.2; then
		ok "the Arista agrees it is DR on 10.0.12.0/24"
	else
		fail "the Arista says the DR on 10.0.12.0/24 is '$(eos_dr Ethernet1)', expected 10.0.12.2"
		dprint "$(eos 'show ip pim interface')"
	fi
	if wait_for 60 pimd_dr_is r3 epair823b 10.0.23.3; then
		ok "R3 made itself DR on 10.0.23.0/24"
	else
		fail "R3 says the DR on 10.0.23.0/24 is '$(pimd_dr r3 epair823b)', expected 10.0.23.3"
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
	if [ "$FAILED" -eq 0 ]; then
		print "$SCENARIO: all assertions passed"
	else
		print "$SCENARIO: $FAILED assertion(s) failed"
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

case ${1:-} in
start) set_scenario "${2:-}"; start ;;
check)
	set_scenario "${2:-}"
	check
	rc=$?
	verdict
	exit $rc
	;;
run)
	if [ "${2:-}" = all ]; then
		# Every scenario runs even when an earlier one failed: the
		# point of a second implementation is the whole matrix, and
		# a red first scenario says nothing about the second.
		total=0
		for s in $SCENARIOS; do
			run_one "$s" || total=$((total + 1))
		done
		[ "$total" -eq 0 ] || die "$total scenario(s) failed"
		exit 0
	fi
	run_one "${2:-}"
	exit $?
	;;
stop) set_scenario "${2:-}"; stop ;;
*) usage; exit 2 ;;
esac

# Local Variables:
#  indent-tabs-mode: t
#  c-file-style: "linux"
# End:
