# shellcheck shell=sh
# The Linux side of lab.sh, the same functions as lab-freebsd.sh
# over the same topology tables: the boxes are named network namespaces
# (ip-netns(8)), the links veth pairs named as the epairs they stand for,
# the shared segments Linux bridges on the host, and what the kernel made
# of pimd's requests is read back from ip-mroute(8), /proc/net/ip_mr_vif,
# the register vif's own counters and ip-maddress(8).  See the header of
# lab-freebsd.sh for what each function is for.
#
# Needs root (or passwordless sudo), iproute2, ethtool, and a kernel with
# CONFIG_IP_MROUTE and CONFIG_IP_PIMSM_V2.  pimd on Linux always does its
# RPF lookups over netlink, so NETLINK defaults to yes here and cannot be
# anything else.
#
# Named namespaces rather than the unshare(1) of the rest of this
# directory, because a box has to outlive the command that built it: start
# and check are separate invocations, and so is every slot of run -j.

NETLINK=${NETLINK:-yes}

NETNS_PREFIX=pimd${TAG}_

# Where a scenario puts an address the router owns rather than a link
LOOPBACK_IF=lo

# A data Register reaches pimd's raw socket whole, beside the copy
# pim_rcv() (net/ipv4/ipmr.c) decapsulates, so pimd copies data Registers
REGISTER_UPCALL=whole

backend_check_req() {
	[ "$NETLINK" = yes ] || \
		die "pimd on Linux has no routing socket RPF backend, NETLINK=$NETLINK cannot be run"
	command -v ip >/dev/null 2>&1 || die "ip(8) not found, install iproute2"
	command -v ethtool >/dev/null 2>&1 || die "ethtool not found"
	[ -e /proc/net/ip_mr_vif ] || \
		die "kernel has no CONFIG_IP_MROUTE, cannot route multicast"
}

# FreeBSD loops every forwarded packet back into the router that sent it
# unless a host-wide sysctl says otherwise, see lab-freebsd.sh.  Linux has
# no such knob, IP_MULTICAST_LOOP is a socket option only, so there is no
# host state for the slots to share.
disable_mcast_loop() { :; }
restore_mcast_loop() { :; }

nsname() { echo "$NETNS_PREFIX$1"; }

box_exists() { [ -e "/run/netns/$(nsname "$1")" ]; }

box_run() { j=$1; shift; ${SUDO} ip netns exec "$(nsname "$j")" "$@"; }

# sh execs into ip netns exec, which execs into the command without a fork
# of its own, so the PID written is the daemon's, as daemon(8) -p writes it
box_daemon() {
	bd_box=$1
	bd_pid=$2
	bd_log=$3
	shift 3

	${SUDO} sh -c '
		echo $$ > "$1"
		log=$2
		ns=$3
		shift 3
		exec ip netns exec "$ns" "$@" >> "$log" 2>&1
	' box_daemon "$bd_pid" "$bd_log" "$(nsname "$bd_box")" "$@" \
		</dev/null >/dev/null 2>&1 &
}

box_hint() { echo "${SUDO} ip netns exec $(nsname "$1")"; }

box_addr_add() { box_run "$1" ip addr add "$3" broadcast + dev "$2"; }

# ip(8) wants the prefix length of the address it deletes, and the callers
# name the address alone, as ifconfig(8) -alias takes it
box_addr_del() {
	bad_pfx=$(box_run "$1" ip -o -4 addr show dev "$2" 2>/dev/null | \
		awk -v a="$3" '{ split($4, p, "/"); if (p[1] == a) print $4 }')
	[ -n "$bad_pfx" ] || return 1
	box_run "$1" ip addr del "$bad_pfx" dev "$2"
}

# A veth goes with its peer, as an epair does
box_if_destroy() { box_run "$1" ip link del "$2"; }

box_if_show() { box_run "$1" ip addr show dev "$2"; }

# The metric is part of what names a Linux route, so a route cannot be
# given a new one in place: "replace" with another metric adds a second
# route beside the first, which keeps winning.  Take them all out first.
box_route_change() {
	if [ $# -ge 4 ]; then
		box_run "$1" ip route flush exact "$2" && \
			box_run "$1" ip route add "$2" via "$3" metric "$4"
	else
		box_run "$1" ip route replace "$2" via "$3"
	fi
}

route_has_metric() { :; }

# Prefix length of a dotted netmask
mask_len() {
	echo "$1" | awk -F. '{
		n = 0
		for (i = 1; i <= 4; i++)
			for (b = 128; b >= 1; b /= 2)
				if ($i >= b) { n++; $i -= b }
		print n
	}'
}

# The same bridged segments as lab-freebsd.sh, and mcast_snooping off on
# them: a snooping bridge floods a group only to the ports it has heard
# a report on, and the PIM routers on a segment never report the groups
# they forward.  The "a" ends stay on the bridge, the "b" ends are moved
# into the boxes by create_box().
create_lans() {
	is_shared_lan || return 0

	for br in $BR_UPSTREAM $BR_RECEIVER; do
		if ip link show "$br" >/dev/null 2>&1; then
			die "$br already exists, it is not ours to reuse"
		fi
	done

	for br in $BR_UPSTREAM $BR_RECEIVER; do
		${SUDO} ip link add "$br" type bridge mcast_snooping 0
		${SUDO} ip link set "$br" up
	done

	for e in $BR_UPSTREAM_EPAIRS $BR_RECEIVER_EPAIRS; do
		${SUDO} ip link add "${e}a" type veth peer name "${e}b"
		${SUDO} ethtool -K "${e}a" tx off rx off >/dev/null
		${SUDO} ip link set "${e}a" up
	done

	for e in $BR_UPSTREAM_EPAIRS; do
		${SUDO} ip link set "${e}a" master "$BR_UPSTREAM"
	done
	for e in $BR_RECEIVER_EPAIRS; do
		${SUDO} ip link set "${e}a" master "$BR_RECEIVER"
	done
}

create_box() {
	box=$1
	name=$(nsname "$box")

	if box_exists "$box"; then
		die "network namespace $name already exists, it is not ours to reuse"
	fi

	${SUDO} ip netns add "$name"
	box_run "$box" ip link set lo up

	# Before any interface arrives, which takes its settings from
	# "default" as it enters the namespace.  rp_filter is 2 on most
	# distributions and a namespace inherits it, which drops a Register
	# decapsulated on the register vif and anything that arrives on a
	# link the unicast routes do not point back out of.  promote_secondaries
	# is what FreeBSD does anyway: deleting an interface's first address
	# keeps the others, where Linux would otherwise delete them all.
	box_run "$box" sysctl -qw \
		net.ipv4.conf.all.rp_filter=0 \
		net.ipv4.conf.default.rp_filter=0 \
		net.ipv4.conf.all.promote_secondaries=1 \
		net.ipv4.conf.default.promote_secondaries=1

	# The "a" end creates both ends of the pair.  Checksum offload goes
	# off on each end, or a packet that leaves the kernel -- into a
	# Register, or a raw socket -- carries a checksum nobody computed.
	for i in $(ifaces "$box"); do
		case $i in
		*a) ${SUDO} ip link add "$i" type veth peer name "${i%a}b" ;;
		esac
		${SUDO} ip link set "$i" netns "$name"
		box_run "$box" ethtool -K "$i" tx off rx off >/dev/null
	done

	set -- $(renames "$box")
	while [ $# -ge 2 ]; do
		box_run "$box" ip link set "$1" name "$2"
		shift 2
	done

	set -- $(addrs "$box")
	while [ $# -ge 2 ]; do
		box_run "$box" ip addr add "$2" broadcast + dev "$1"
		box_run "$box" ip link set "$1" up
		shift 2
	done

	set -- $(aliases "$box")
	while [ $# -ge 2 ]; do
		box_run "$box" ip addr add "$2" broadcast + dev "$1"
		shift 2
	done

	set -- $(tunnels "$box")
	if [ $# -ge 5 ]; then
		${SUDO} modprobe ipip || die "cannot load ipip, needed for the tunnel"
	fi
	# A fixed outer TTL, as gif(4) has: the default "inherit" copies the
	# TTL of 1 every Hello and Join carries onto the outer header, and the
	# router in the middle drops them all
	while [ $# -ge 5 ]; do
		box_run "$box" ip tunnel add "$1" mode ipip local "$2" remote "$3" ttl 64
		box_run "$box" ip addr add "$4" peer "$5/$(mask_len "$GIF_MASK")" dev "$1"
		box_run "$box" ip link set "$1" up
		shift 5
	done

	set -- $(routes "$box")
	while [ $# -ge 2 ]; do
		box_run "$box" ip route add "$1" via "$2"
		shift 2
	done

	set -- $(route_metrics "$box")
	while [ $# -ge 3 ]; do
		box_route_change "$box" "$1" "$2" "$3"
		shift 3
	done

	case $box in
	r*) box_run "$box" sysctl -qw net.ipv4.ip_forward=1 ;;
	esac
}

# The veths inside go with the namespace, once the last process in it has
# gone, which stop() has seen to
destroy_box() {
	box_exists "$1" || return 0
	${SUDO} ip netns del "$(nsname "$1")" 2>/dev/null || true
}

# What is left on the host: the "a" ends on the bridges, the bridges, and
# any pair whose namespace was never made
destroy_links() {
	sleep 1
	for e in $ALL_EPAIRS; do
		for end in a b; do
			${SUDO} ip link del "$e$end" 2>/dev/null || true
		done
	done

	for br in $BR_UPSTREAM $BR_RECEIVER; do
		${SUDO} ip link del "$br" 2>/dev/null || true
	done
}

MFC_SHOW_CMD="ip mroute show"

mfc_show() { box_run "$1" $MFC_SHOW_CMD; }

has_mfc() { box_run "$1" ip mroute show 2>/dev/null | grep -q "$2"; }

# ip mroute names the outgoing interfaces, "Oifs: eth1 eth2(ttl 2)", and
# the kernel's vif table is what maps the vif pimd asked about onto one
mfc_forwards_on() {
	mfo_if=$(box_run "$1" cat /proc/net/ip_mr_vif 2>/dev/null | \
		awk -v v="$4" '$1 == v { print $2 }')
	[ -n "$mfo_if" ] || return 1

	box_run "$1" ip mroute show 2>/dev/null | awk -v k="($2,$3)" -v i="$mfo_if" '
		$1 == k {
			for (f = 1; f <= NF; f++) {
				if ($f != "Oifs:")
					continue
				for (g = f + 1; g <= NF && $g != "State:"; g++) {
					split($g, oif, "(")
					if (oif[1] == i)
						found = 1
				}
			}
		}
		END { exit !found }
	'
}

# Local address of one VIF index, as the kernel has it.  pimd adds a Linux
# vif by interface index, VIFF_USE_IFINDEX in uvif_to_vifctl() (src/kern.c),
# so the kernel keeps no address for it: "Local" in /proc/net/ip_mr_vif is
# the ifindex, and the vif is on whatever address that interface has.  That
# is the answer given here, the interface's first IPv4 address, and nothing
# for the register vif, which has neither.  A vif pimd failed to put back
# has no row, and no answer either.
kern_vif_addr() {
	kva_idx=$(box_run "$1" cat /proc/net/ip_mr_vif 2>/dev/null | awk -v v="$2" '
		function hex(s,    i, n) {
			n = 0
			for (i = 1; i <= length(s); i++)
				n = n * 16 + index("0123456789ABCDEF", toupper(substr(s, i, 1))) - 1
			return n
		}
		# VIFF_USE_IFINDEX is 0x8
		$1 == v && int(hex($7) / 8) % 2 { print hex($8) }
	')
	[ -n "$kva_idx" ] || return 0

	kva_if=$(box_run "$1" ip -o link show 2>/dev/null | \
		awk -F': ' -v i="$kva_idx" '$1 == i { sub(/@.*/, "", $2); print $2 }')
	[ -n "$kva_if" ] || return 0

	box_run "$1" ip -o -4 addr show dev "$kva_if" 2>/dev/null | \
		awk '{ split($4, p, "/"); print p[1]; exit }'
}

# Data Registers the kernel decapsulated.  pim_rcv() (net/ipv4/ipmr.c)
# hands the inner packet in on the register vif's device, pimreg, and
# counts it there; a Null-Register is not decapsulated and not counted, as
# FreeBSD counts only data Registers.
registers_rcvd() {
	box_run "$1" cat /sys/class/net/pimreg/statistics/rx_packets 2>/dev/null
}

# One group per line.  Exits non-zero for an interface ip(8) cannot find.
if_memberships() {
	im_held=$(box_run "$1" ip -f inet maddr show dev "$2" 2>/dev/null) || return 1
	echo "$im_held" | awk '$1 == "inet" { print $2 }'
}
