# shellcheck shell=sh
# The FreeBSD side of lab.sh: every place the lab builds, drives or
# reads something through the operating system rather than through pimd.
# The boxes are vnet jails, the links epairs, the shared segments if_bridge
# on the host, and what the kernel made of pimd's requests is read back with
# netstat(1) and ifmcstat(8).
#
# lab.sh sources this once the slot is known, and its scenarios
# reach the host through nothing but the functions below, so a lab on
# another system is another file of the same functions rather than another
# copy of the scenarios.  Nothing here runs on its own.
#
#   backend_check_req                   the host can hold a lab at all
#   disable_mcast_loop                  host state a router needs, taken and
#   restore_mcast_loop                  given back in turns by every slot
#   create_lans                         the shared segments of the scenario
#   create_box BOX, destroy_box BOX     one box, with its links, addresses
#                                       and routes, from the topology tables
#   destroy_links                       what destroy_box leaves on the host
#   box_exists BOX                      is the box up
#   box_run BOX CMD...                  run CMD inside the box
#   box_daemon BOX PIDFILE LOG CMD...   run CMD inside the box, detached,
#                                       with $PIMD_ENV in its environment
#   box_hint BOX                        what a human types to reach the box
#   box_addr_add BOX IF ADDR/LEN        add an address beside the others
#   box_addr_del BOX IF ADDR            remove one address
#   box_if_destroy BOX IF               take an interface away
#   box_if_show BOX IF                  dump an interface, for a failure
#   box_route_change BOX DEST GW [METRIC]
#   route_has_metric                    can a route be given a metric here
#   has_mfc BOX GROUP                   the kernel forwards the group
#   mfc_forwards_on BOX SRC GROUP VIF   ... and out of that vif
#   mfc_show BOX                        dump the kernel's multicast state,
#                                       which $MFC_SHOW_CMD names
#   kern_vif_addr BOX VIF               local address of one kernel vif
#   registers_rcvd BOX                  Registers the kernel decapsulated
#   if_memberships BOX IF               groups the interface is a member of
#   $LOOPBACK_IF                        the loopback interface's name
#   $REGISTER_UPCALL                    what of a data Register the kernel
#                                       hands pimd, "headers" or "whole"

JAIL_PREFIX=pimd${TAG}_

# Where a scenario puts an address the router owns rather than a link
LOOPBACK_IF=lo0

# pim_input() (sys/netinet/ip_mroute.c) hands pimd only the headers of a
# data Register, so what pimd copies to another Anycast-RP member is a
# Null-Register
REGISTER_UPCALL=headers

# The ifconfig(8) group every interface this lab creates is put in, so a
# human can find or destroy one lab's links and not another's.  The slot
# is spelled in letters, digit by digit -- slot 0 is "pimda" and slot 31
# "pimddb" -- because a group name may not end in a digit: it would be
# ambiguous with an interface name, and setifgroup refuses it outright.
IFGROUP=pimd$(echo "$SLOT" | tr 0-9 a-j)

backend_check_req() {
	[ "$(sysctl -n kern.features.vimage 2>/dev/null || echo 0)" = "1" ] || \
		die "kernel has no VIMAGE support, cannot create vnet jails"
	# ip_mroute is a module on GENERIC and a jail may not kldload
	${SUDO} kldload -n ip_mroute 2>/dev/null || \
		die "cannot load ip_mroute.ko, kernel has no multicast routing"
	# Same for netlink: a pimd built --enable-netlink opens its routing
	# socket in the jail, and the module has to be there before it does
	if [ "$NETLINK" = yes ]; then
		${SUDO} kldload -n netlink 2>/dev/null || \
			die "cannot load netlink.ko, needed for NETLINK=yes"
	fi
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
# jail: the value has to be changed on the host.
#
# It is therefore the one thing the slots cannot each have their own of,
# and the one thing a lab must not restore on its own: a stop that put the
# host value back while another slot -- or freebsd-interop.sh, which wants
# the same 0 -- was still forwarding would black-hole that run, for the
# reason spelled out above, and it would do it silently.  So the value is
# saved once, by whichever lab arrives first, in a directory on the host
# that every lab shares; each one leaves a file of its own there while it
# runs, and the last to leave is the one that puts the value back.
#
# lockf(1) around both halves, because a pool of slots starts one scenario
# as another finishes, which is exactly when "am I the first" and "am I the
# last" are asked at the same moment.  It holds a real flock, so a lab that
# is killed outright leaves no stale lock behind -- only, as before, a
# sysctl still at 0, which the next stop on that slot puts right.
MCAST_LOOP_DIR=${MCAST_LOOP_DIR:-/var/run/pimd-lab-mcastloop}
MCAST_LOOP_LOCK=$MCAST_LOOP_DIR.lock
MCAST_LOOP_TOKEN=lab$SLOT

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

jname() { echo "$JAIL_PREFIX$1"; }

box_exists() { jls -j "$(jname "$1")" jid >/dev/null 2>&1; }

box_run() { j=$1; shift; ${SUDO} jexec "$(jname "$j")" "$@"; }

# daemon(8) opens the log with O_APPEND, so a box restarted in the middle of
# a scenario adds to what the first incarnation logged
box_daemon() {
	bd_box=$1
	bd_pid=$2
	bd_log=$3
	shift 3

	# shellcheck disable=SC2086
	${SUDO} daemon -f -p "$bd_pid" -o "$bd_log" \
		jexec "$(jname "$bd_box")" ${PIMD_ENV:+env $PIMD_ENV} "$@"
}

box_hint() { echo "${SUDO} jexec $(jname "$1")"; }

box_addr_add() { box_run "$1" ifconfig "$2" inet "$3" alias; }

box_addr_del() { box_run "$1" ifconfig "$2" inet "$3" -alias; }

box_if_destroy() { box_run "$1" ifconfig "$2" destroy; }

box_if_show() { box_run "$1" ifconfig "$2"; }

box_route_change() {
	if [ $# -ge 4 ]; then
		box_run "$1" route -q change "$2" "$3" -metric "$4"
	else
		box_run "$1" route -q change "$2" "$3"
	fi
}

# route(8) learned -metric in FreeBSD 16 (2e2d402d061d); 15.x rejects it
# as a bad keyword, before it reaches the kernel, so a "get" is enough to
# ask without touching a table.
route_has_metric() {
	route -n get -metric 1 127.0.0.1 >/dev/null 2>&1
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

	${SUDO} ifconfig "$BR_UPSTREAM" create group "$IFGROUP" up >/dev/null
	${SUDO} ifconfig "$BR_RECEIVER" create group "$IFGROUP" up >/dev/null

	for e in $BR_UPSTREAM_EPAIRS $BR_RECEIVER_EPAIRS; do
		${SUDO} ifconfig "$e" create group "$IFGROUP" >/dev/null
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
		*a) ${SUDO} ifconfig "${i%a}" create group "$IFGROUP" >/dev/null ;;
		esac
		vnetargs="$vnetargs vnet.interface=$i"
	done

	# shellcheck disable=SC2086
	${SUDO} jail -c name="$name" host.hostname="$box" persist vnet $vnetargs

	set -- $(renames "$box")
	while [ $# -ge 2 ]; do
		box_run "$box" ifconfig "$1" name "$2"
		shift 2
	done

	set -- $(addrs "$box")
	while [ $# -ge 2 ]; do
		box_run "$box" ifconfig "$1" inet "$2" up
		shift 2
	done

	# After the addresses: "alias" is what keeps the kernel from
	# replacing the address the interface already has
	set -- $(aliases "$box")
	while [ $# -ge 2 ]; do
		box_run "$box" ifconfig "$1" inet "$2" alias
		shift 2
	done

	# Before the routes: gif-tunnel points some of them at $GIF_R1/$GIF_R3
	set -- $(tunnels "$box")
	while [ $# -ge 5 ]; do
		box_run "$box" ifconfig "$1" create
		box_run "$box" ifconfig "$1" tunnel "$2" "$3"
		box_run "$box" ifconfig "$1" inet "$4" "$5" netmask "$GIF_MASK" up
		shift 5
	done

	set -- $(routes "$box")
	while [ $# -ge 2 ]; do
		box_run "$box" route -q add "$1" "$2" >/dev/null
		shift 2
	done

	# After the routes: a metric is a property of one that already exists
	set -- $(route_metrics "$box")
	while [ $# -ge 3 ]; do
		box_run "$box" route -q change "$1" "$2" -metric "$3" >/dev/null
		shift 3
	done

	case $box in
	r*) box_run "$box" sysctl -q net.inet.ip.forwarding=1 >/dev/null ;;
	esac
}

destroy_box() {
	box=$1
	name=$(jname "$box")

	jls -j "$name" jid >/dev/null 2>&1 || return 0
	${SUDO} jail -r "$name" 2>/dev/null || true
}

# Jails can linger in the dying state and hold their interfaces, so the
# epairs and bridges on the host are destroyed only once they are gone
destroy_links() {
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
}

MFC_SHOW_CMD="netstat -gn"

mfc_show() { box_run "$1" $MFC_SHOW_CMD; }

has_mfc() { box_run "$1" netstat -gn 2>/dev/null | grep -q "$2"; }

mfc_forwards_on() {
	box_run "$1" netstat -gn 2>/dev/null | awk -v s="$2" -v g="$3" -v v="$4" '
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

# Local address the kernel holds for one VIF index, out of "netstat -gn".
# VIF 0 is the register VIF: uvifs[0] is reserved for it, which is why
# config_vifs_from_kernel() starts its loop at 1 (src/config.c), and the
# kernel index is the same one.
kern_vif_addr() {
	box_run "$1" netstat -gn 2>/dev/null | awk -v v="$2" '$1 == v { print $3 }'
}

# How many PIM Registers the kernel in $1's vnet has taken in, out of
# netstat(1).  pim_input() (sys/netinet/ip_mroute.c) counts one here, and
# hands the inner packet to if_simloop() on the register vif, before the
# daemon is given its copy of the header -- so this is what arrived and was
# decapsulated, whatever pimd then made of it.  The counter is per vnet,
# pimstat being a VNET_PCPUSTAT, so it is this jail's own.
#
# Both halves of the pattern are load bearing.  netstat writes "1 data
# register message received" and "2 data register messages received", and
# the RP that accepts a Register stops the DR after the first one, so a
# plural-only match reads zero on exactly the run that should show one.
# The trailing anchor keeps out the "... received on wrong iif" line, which
# is a superstring of this one.
registers_rcvd() {
	box_run "$1" netstat -sp pim 2>/dev/null | \
		awk '/data register messages? received$/ { print $1; exit }'
}

# One group per line.  Exits non-zero, rather than printing nothing, for an
# interface ifmcstat cannot resolve: an interface that cannot be read holds
# nothing we can prove it holds, which is not the same as holding it all.
if_memberships() {
	im_held=$(box_run "$1" ifmcstat -i "$2" -f inet 2>/dev/null) || return 1
	echo "$im_held" | awk '$1 == "group" { print $2 }'
}
