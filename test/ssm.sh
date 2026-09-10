#!/bin/sh
# Verifies the IGMPv3 (S,G) membership state of a last hop router:
#  - a report with two sources for one SSM group creates both
#  - blocking one of them leaves the other alone
#  - the survivor still ages out when the reports stop
#  - a report with more sources than pimd keeps is bounded, not fatal
#
# The third one is the regression this test exists for.  Each group used
# to hold a single membership timer, whichever source reported last, so
# blocking that source left the group with sources and no timer running:
# the membership never expired again, no matter how long the receiver had
# been gone.  A leave for the last source still cleaned up, which is why
# this needs a receiver that stops reporting rather than one that leaves.
#
#        netns "left"                    router (this netns)
#      ED  10.0.0.10/24 --- eth0/a1 --- 10.0.0.1/24
#                                       10.0.1.1/24 --- a2 (no members)
#
# The reports are injected with the igmpv3 tool rather than by joining a
# group on ED: a kernel would answer every query afterwards and the
# membership would never age out, which is precisely what is measured.

# shellcheck source=/dev/null
. "$(dirname "$0")/lib.sh"

# Membership timeout is IGMP_ROBUSTNESS_VARIABLE * query-interval +
# IGMP_QUERY_RESPONSE_INTERVAL, i.e. 3 * 5 + 10 with the .conf below.
QUERY_INTERVAL=5
TIMEOUT=25
GROUP=232.1.1.1
SRC1=10.0.2.10
SRC2=10.0.2.11

print "Creating world ..."
left="/tmp/$NM/a1"
touch "$left"
PID=$$

echo "$left" > "/tmp/$NM/mounts"
lif=$(basename "$left")

unshare --net="$left" -- ip link set lo up
nsenter --net="$left" -- ip link add eth0 type veth peer "$lif"
nsenter --net="$left" -- ip link set "$lif" netns $PID
nsenter --net="$left" -- ip link set eth0 up
ip link set "$lif" up

ip addr add 10.0.0.1/24 dev "$lif"
nsenter --net="$left" -- ip addr add 10.0.0.10/24 dev eth0
nsenter --net="$left" -- ip route add default via 10.0.0.1

# A second interface, so the router has somewhere to send a Join towards
# the sources and pimd is not running with a single vif
ip link add a2 type dummy
ip link set a2 up
ip link set a2 multicast on
ip addr add 10.0.1.1/24 dev a2
ip route add 10.0.2.0/24 via 10.0.1.2 dev a2

ip -br l
ip -br a

print "Creating config ..."
cat <<EOF > "/tmp/$NM/conf"
no phyint
phyint $lif enable
phyint a2 enable

bsr-candidate priority 5 interval 3
rp-candidate priority 20 interval 3

# Keeps the membership timeout at $TIMEOUT sec instead of the 385 the
# default query interval gives, the test has to outlive it twice
igmp-query-interval $QUERY_INTERVAL
EOF
cat "/tmp/$NM/conf"

print "Starting pimd ..."
../src/pimd -i "$NM" -f "/tmp/$NM/conf" -n -p "/tmp/$NM/pid" -l debug -d igmp \
	    -u "/tmp/$NM/sock" &
echo $! >> "/tmp/$NM/PIDs"
sleep 8

PIMCTL="../src/pimctl -u /tmp/$NM/sock"

# Source lines pimd holds for $GROUP on the receiver LAN.  "show igmp"
# prints one line per (group, source), and "ANY" in the source column for
# an any-source membership, so this counts (S,G) memberships only.
sources()
{
	$PIMCTL -t show igmp 2>/dev/null | \
		awk -v ifn="$lif" -v grp="$GROUP" \
		    '$1 == ifn && $2 == grp && $3 != "ANY" { print $3 }'
}

count_sources()
{
	sources | wc -l
}

report()
{
	nsenter --net="$left" -- ./igmpv3 -i 10.0.0.10 -g "$GROUP" "$@"
}

print "1. A report with two sources creates both memberships"
report -t allow "$SRC1" "$SRC2"
sleep 2
$PIMCTL show igmp
num=$(count_sources)
echo " => $num (S,G) memberships, expected 2"
[ "$num" -eq 2 ] || FAIL "pimd did not create one membership per reported source"

print "2. Blocking one source keeps the other"
report -t block "$SRC2"
sleep 2
$PIMCTL show igmp
num=$(count_sources)
left_src=$(sources)
echo " => $num (S,G) memberships, expected 1: $left_src"
[ "$num" -eq 1 ] || FAIL "blocking one source of two did not leave exactly one"
[ "$left_src" = "$SRC1" ] || FAIL "blocking $SRC2 removed $left_src instead"

print "3. The surviving membership ages out once the reports stop"
dprint "waiting $((TIMEOUT + 15))s, membership timeout is ${TIMEOUT}s"
sleep $((TIMEOUT + 15))
$PIMCTL show igmp
num=$(count_sources)
echo " => $num (S,G) memberships, expected 0"
[ "$num" -eq 0 ] || FAIL "membership never expired, no timer left after the block"

print "4. A report with more sources than pimd keeps is bounded"
report -t allow -n 400 -b 10.0.2.100
sleep 2
if ! $PIMCTL show status >/dev/null 2>&1; then
	FAIL "pimd stopped answering after a 400 source report"
fi
num=$(count_sources)
echo " => $num (S,G) memberships, expected 1..256"
# shellcheck disable=SC2166
[ "$num" -ge 1 -a "$num" -le 256 ] || FAIL "source list is not bounded, $num entries"

kill_pids

OK
