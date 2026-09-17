#!/bin/sh
# Verify Anycast-RP using PIM (RFC 4610): two RPs holding one RP address,
# kept in sync by copying each other Registers instead of running MSDP.
#
#          10.0.1/24         10.0.12/24          10.0.23/24         10.0.3/24
#     ED1 ----------- R1 ---------------- R2 ---------------- R3 ----------- ED2
#     eth0       eth0    eth1        eth0    eth1        eth0    eth1        eth0
#
#     X = 10.0.99.1/32, the anycast RP address, on the loopback of the members
#
# Run twice over the same chain, with the set in two places:
#
# 1. Copies.  R2 and R3 hold X, R1's route to X goes to R2, and ED2's
#    shared tree ends at R3.  R1 registers to R2 only, so ED2 is reached
#    only if R2 copies the Registers to R3.  On Linux the kernel hands
#    pimd the whole Register, so the copy is a data Register -- the one
#    thing lab.sh's anycast scenario cannot see, its kernel
#    passing pimd only the headers.
#
# 2. The RP as DR.  R1 and R3 hold X, R2's route to X goes to R1, which is
#    then the RP of the group and the DR of the source at once, and is sent
#    no Register to copy.  ED2 is reached only if R1 registers its own
#    source to R3 itself, from its member address.
#
# What every step asserts is traffic at ED2.  The logs say which mechanism
# carried it: the "Copy PIM Register" and "Send PIM Register" lines, and
# the length R3's pimd was handed, which on Linux is the length on the wire.
#
# The half without a set, which shows ED2 is not reached otherwise, is in
# test/lab.sh (anycast and anycast-dr); it does not depend on the
# kernel.

# pimd debug, when enabled pimctl calls at runtime are also enabled
DEBUG="-l debug -d pim_register"

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

print "Check deps ..."
check_dep ethtool

ANY=10.0.99.1
R2_ID=10.0.23.2
R3_ID=10.0.23.3
R1_ID=10.0.12.1

print "Creating world ..."
ED1="/tmp/$NM/ED1"
R1="/tmp/$NM/R1"
R2="/tmp/$NM/R2"
R3="/tmp/$NM/R3"
ED2="/tmp/$NM/ED2"
for ns in "$ED1" "$R1" "$R2" "$R3" "$ED2"; do
    touch "$ns"
    echo "$ns" >> "/tmp/$NM/mounts"
    unshare --net="$ns" -- ip link set lo up
done

# A veth pair between two namespaces: $1:$2 and $3:$4, addresses $5 and $6.
# The far end is moved by the PID of a process living in that namespace,
# ip(8) has no way to name a netns bound to a file.
link()
{
    nsenter --net="$3" -- sleep 10 &
    pid=$!
    nsenter --net="$1" -- ip link add "$2" type veth peer name "$4" netns "$pid"
    kill "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null

    ifsetup "$1" "$2"
    ifsetup "$3" "$4"
    nsenter --net="$1" -- ip addr add "$5" broadcast + dev "$2"
    nsenter --net="$3" -- ip addr add "$6" broadcast + dev "$4"
}

link "$ED1" eth0 "$R1"  eth0 10.0.1.10/24 10.0.1.1/24
link "$R1"  eth1 "$R2"  eth0 10.0.12.1/24 10.0.12.2/24
link "$R2"  eth1 "$R3"  eth0 10.0.23.2/24 10.0.23.3/24
link "$R3"  eth1 "$ED2" eth0 10.0.3.1/24  10.0.3.10/24

nsenter --net="$ED1" -- ip route add default via 10.0.1.1
nsenter --net="$ED2" -- ip route add default via 10.0.3.1
nsenter --net="$R1"  -- ip route add 10.0.23.0/24 via 10.0.12.2
nsenter --net="$R1"  -- ip route add 10.0.3.0/24  via 10.0.12.2
nsenter --net="$R2"  -- ip route add 10.0.1.0/24  via 10.0.12.1
nsenter --net="$R2"  -- ip route add 10.0.3.0/24  via 10.0.23.3
nsenter --net="$R3"  -- ip route add 10.0.1.0/24  via 10.0.23.2
nsenter --net="$R3"  -- ip route add 10.0.12.0/24 via 10.0.23.2

for ns in "$R1" "$R2" "$R3"; do
    nsenter --net="$ns" -- sysctl -qw net.ipv4.ip_forward=1
    nsenter --net="$ns" -- sysctl -qw net.ipv4.conf.all.rp_filter=0
done

print "Verifying unicast routing ..."
tenacious 30 nsenter --net="$ED1" -- ping -qc 1 -W 1 10.0.3.10 >/dev/null
dprint "OK"

# Start pimd on the three routers, the set named by the two member
# addresses given, and wait for the neighbours the source tree needs.
start_pimd()
{
    for r in 1 2 3; do
	echo "rp-address $ANY" > "/tmp/$NM/conf$r"
    done
    for r in "$1" "$2"; do
	printf "anycast-rp %s %s\nanycast-rp %s %s\n" "$ANY" "$3" "$ANY" "$4" >> "/tmp/$NM/conf$r"
    done

    for r in 1 2 3; do
	eval ns=\$R$r
	nsenter --net="$ns" -- ../src/pimd -i "r$r$5" -f "/tmp/$NM/conf$r" -n \
		-p "/tmp/$NM/r$r.pid" -u "/tmp/$NM/r$r.sock" $DEBUG \
		> "/tmp/$NM/r$r$5.log" 2>&1 &
	echo $! >> "/tmp/$NM/PIDs"
	echo $! > "/tmp/$NM/r$r.daemon"
    done

    print "Waiting for PIM neighbours ..."
    tenacious 60 has_neighbor "$R3" r3 10.0.23.2
    tenacious 60 has_neighbor "$R2" r2 10.0.12.1
    dprint "OK"
}

stop_pimd()
{
    for r in 1 2 3; do
	kill "$(cat "/tmp/$NM/r$r.daemon")" 2>/dev/null
	wait "$(cat "/tmp/$NM/r$r.daemon")" 2>/dev/null
    done
}

has_neighbor()
{
    sleep 1
    nsenter --net="$1" -- ../src/pimctl -u "/tmp/$NM/$2.sock" show neighbor | grep -q "$3"
}

pimctl()
{
    nsenter --net="$1" -- ../src/pimctl -u "/tmp/$NM/$2.sock" "$3" "$4"
}

# Send 10 mpings from ED1 to group $1, with ED2 joined.  The sender waits
# for 10 replies, and they come back the same way: ED2 is a source behind
# R3 registering to the set as well.
stream()
{
    nsenter --net="$ED2" -- ./mping -r -i eth0 -t 5 -W 90 "$1" &
    echo $! >> "/tmp/$NM/PIDs"
    rcv=$!
    sleep 2

    nsenter --net="$ED1" -- ./mping -s -i eth0 -t 5 -c 10 -w 60 "$1"
    rc=$?
    kill "$rcv" 2>/dev/null
    wait "$rcv" 2>/dev/null
    return $rc
}

# Show the state behind a failure before failing
dump()
{
    for r in 1 2 3; do
	eval ns=\$R$r
	dprint "R$r"
	pimctl "$ns" "r$r" show status | grep -i anycast
	pimctl "$ns" "r$r" show mrt
	nsenter --net="$ns" -- cat /proc/net/ip_mr_vif
    done
    FAIL "$*"
}

print "1. Copies: R2 and R3 hold $ANY, R1 registers to R2"
nsenter --net="$R2" -- ip addr add "$ANY/32" dev lo
nsenter --net="$R3" -- ip addr add "$ANY/32" dev lo
nsenter --net="$R1" -- ip route add "$ANY/32" via 10.0.12.2
start_pimd 2 3 "$R2_ID" "$R3_ID" "-copy"

stream 225.1.2.3 || dump "ED2 is not reached through a copy from R2 to R3"
dprint "ED2 reached"

grep -q "Copy PIM Register from 10.0.1.1 for (10.0.1.10, 225.1.2.3) to Anycast-RP member $R3_ID, TTL 254, data" \
     "/tmp/$NM/r2-copy.log" || dump "R2 logged no data Register copy to $R3_ID"
dprint "R2 copied a data Register to R3, at TTL 254"

# Linux hands pimd the whole Register, so this is what came off the wire:
# more than the 28 bytes of a Register holding only an IP header.
len=$(sed -n "s/.*Received PIM register: len = \([0-9]*\) ttl = 254 from $R2_ID.*/\1/p" \
	  "/tmp/$NM/r3-copy.log" | head -1)
[ "${len:-0}" -gt 28 ] || dump "R3 was handed no data Register from $R2_ID (len '$len')"
dprint "R3 was sent $len bytes from $R2_ID"

grep -q "Copy PIM Register" "/tmp/$NM/r3-copy.log" && dump "R3 copied a Register it was sent by a member"
dprint "R3 copied nothing on"

pimctl "$R2" r2 show status | grep -q "Anycast-RP set .* $R3_ID ([1-9][0-9]* copies)" || \
    dump "R2's show status counts no copies to $R3_ID"
dprint "OK"

stop_pimd
nsenter --net="$R2" -- ip addr del "$ANY/32" dev lo
nsenter --net="$R1" -- ip route del "$ANY/32" via 10.0.12.2

print "2. The RP as DR: R1 and R3 hold $ANY, R1 is the DR of the source"
nsenter --net="$R1" -- ip addr add "$ANY/32" dev lo
nsenter --net="$R2" -- ip route add "$ANY/32" via 10.0.12.1
start_pimd 1 3 "$R1_ID" "$R3_ID" "-dr"

stream 225.1.2.4 || dump "ED2 is not reached through R1 registering to R3"
dprint "ED2 reached"

grep -q "Send PIM Register for (10.0.1.10, 225.1.2.4) to Anycast-RP member $R3_ID, data" \
     "/tmp/$NM/r1-dr.log" || dump "R1 logged no data Register to $R3_ID"
dprint "R1 registered its own source to R3"

# Routed once, by R2, on the way
len=$(sed -n "s/.*Received PIM register: len = \([0-9]*\) ttl = 254 from $R1_ID.*/\1/p" \
	  "/tmp/$NM/r3-dr.log" | head -1)
[ "${len:-0}" -gt 28 ] || dump "R3 was handed no data Register from $R1_ID (len '$len')"
dprint "R3 was sent $len bytes from $R1_ID"

grep -q "Received PIM_REGISTER_STOP from RP $R3_ID" "/tmp/$NM/r1-dr.log" || \
    dump "R1 got no Register-Stop from $R3_ID"
dprint "OK"

OK
