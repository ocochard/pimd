RFC 7761 compliance
===================

What pimd does that RFC 7761 says it should not, and what RFC 7761 asks for
that pimd does not do.  This is a work list, not a conformance statement: an
entry is here because somebody read the spec section and the code side by side
and found them to disagree.

pimd was written to RFC 2362 and retrofitted towards RFC 4601 and RFC 7761, so
a good part of what follows is not a bug in the sense of "this used to work".
It is the older protocol still showing through, and several entries say which
older behaviour is being kept.  Section numbers below are RFC 7761's unless
another RFC is named; `doc/rfc7761.txt` and `doc/rfc2362.txt` are both in the
tree, so check the text rather than going from memory.  Every entry ends with a
`Check:` pointer giving the section and the line of `doc/rfc7761.txt` where the
rule it is measured against is written, so the reader lands on the sentence and
not just on the section — the RFC's own section numbering is in the table of
contents at `doc/rfc7761.txt:78`.

Sections covered: 4.2 (data packet forwarding, SPTbit), 4.3 (DR and Hello),
4.4 (Register), 4.5 (Join/Prune, both directions), 4.6 (Assert), 4.10 and 4.11
(timers), plus the packet formats in 4.9 where a parser or builder depends on
them.  Not yet read against the code: 4.7 (BSR and RP discovery, which has its
own RFC 5059), 4.8 (SSM), 4.9 as a whole, and the security considerations.

Each entry carries an effort estimate.  "Small" means a localized change,
"medium" means new bookkeeping in existing structures, "large" means state
pimd does not have today.  When one is fixed, delete the entry; when one is
confirmed to be intentional, move it to the last section with the reason.

A deviation that a test reproduces should be asserted through `xfail()`, in
`test/freebsd-lab.sh` or `test/freebsd-interop.sh`, rather than left
unasserted, so that it flips to `ok` the day it is fixed.  Five are carried
that way and all five report `ok`, so every one of them is now a tripwire
against the deviation coming back rather than a live report: the assert
RPT-bit entry of 4.6.1 in `shared-lan-spt`, the SPTbit entry of 4.2.2 in
`assert-lan`, the assert winner state of 4.6.1 and 4.6.2, which `assert-lan`
asserts from both sides, and the (S,G) machine's reach past a lost (\*,G),
which the `rpt-bit` sub-case of `assert-lan` asks for.  A `KNOWN` line in a
run is therefore a regression, not an expected result.

Every entry below ends with a `Test:` note saying what reproduces it, and
every one of them now says `none` -- M4's fixed half is the only thing any
test covers.  The point of writing it down is that the gap is visible from
this list rather than only from grepping the labs.  Where an entry names a
scenario without asserting anything, it is because that scenario builds the
topology the deviation needs and stops short of the assertion; those are the
cheap ones to close.  Several are not
blackbox-testable at all, and say so: a five-second latency or a startup race
cannot be told from a slow lab.


Input validation and trust
--------------------------

Every entry this section held is fixed: V1, an unbounded parse in
`receive_pim_register_stop()`; V2, Join/Prune and Assert accepted from any
host on the subnet; V3, a Register creating routing state before the
I\_am\_RP test; and V4, a freed neighbor left in `mrt->upstream` by an
assert.  The section stays, and keeps its numbering, because these are the
entries where a compliance gap was also a way in, and the next reader should
know they were looked for rather than wonder.

A later audit of the code around the register path added two more, and both
are fixed as well.  Neither is an RFC deviation: the boundary they sit on is
the kernel's, not the wire's, so there is no section to measure them against.
They are here rather than nowhere for the reason the paragraph above gives,
and because the path they guard is the one V3 above and I1 and I2 below are
all about: what a DR does with the packet it is asked to register.

**V5.  A kernel upcall was read for more than it had delivered.**
`accept_igmp()` (`src/igmp.c`) admits a datagram once it is as long as an IP
header, and hands it to `process_kernel_call()` (`src/route.c`) when the
protocol field is zero, which is how the kernel marks an upcall rather than a
packet.  Past that the length went unmentioned.  Two reads stood on it: the
`struct igmpmsg` read there is the same 20 bytes only because the kernel
header lays it out that way and says so, "note the convenient similarity to
an IP packet"; and an `IGMPMSG_WHOLEPKT` upcall reached `send_pim_register()`
(`src/pim_proto.c`) with a pointer past that header, where the encapsulated IP
header was read, and then copied into the Register, for the `ntohs(ip->ip_len)`
it claims about itself.  A header claiming more than the kernel delivered
would have had the DR unicast the bytes that followed it in `igmp_recv_buf` to
the RP.  The received length is a parameter of all three functions now, the
claimed length is compared against what is left of the datagram before it is
used, and a malformed upcall returns before `find_route()` creates state for
it -- which is V3's rule, arrived at from the other side.
*Check: no RFC rule to check against; this is pimd's own kernel interface.
What keeps it off the wire is the `ip_p == 0` test in `accept_igmp()`: a raw
IGMP socket sees protocol 2 from a real packet, so only the kernel reaches the
branch, and both Linux and FreeBSD hand up the whole packet.  Hardening, not a
repair.  Test: nothing reproduces it, and nothing cheaply could -- it wants a
kernel that truncates an upcall or lies about `ip_len`.  What the labs give is
the other half, that the guards refuse nothing a real kernel sends: `rpt`,
`keepalive`, `rp-lasthop`, `rp-offpath` and both `gif-tunnel` scenarios of
`test/freebsd-lab.sh` register through this path, and `arista-rp` and
`pimd-rp` of `test/freebsd-interop.sh` have an EOS decapsulate what pimd
sends and pimd decapsulate what EOS sends.  All of them pass with the checks
in.  That is a net under the fix, not a test of the deviation.*

**V6.  The upcall's interface index was not bounded by the interfaces we
have.**  `process_cache_miss()` and `process_wrong_iif()` (`src/route.c`) take
`im_vif` out of the same message and index `uvifs[]` with it, first in the
debug log that prints the interface name and then to ask whether this router
is the DR there.  `im_vif` is one byte and `uvifs[]` holds `MAXVIFS` entries of
which `numvifs` are in service, so nothing in the message constrained the index
to an interface that exists.  Both refuse an index at or past `numvifs` now.
The bound is `numvifs` and not `MAXVIFS` deliberately: an entry between the two
is inside the array but is not an interface either function could act on.
*Check: no RFC rule; same kernel boundary as V5, found in the same audit and
with the same caveat -- the kernel writes that field.  Test: nothing
reproduces it either, for the same reason: an out-of-range `im_vif` needs a
kernel that invents one.  Every scenario that forwards traffic drives
`process_cache_miss()`, and the ones that move a source onto the shortest
path tree or run an assert drive `process_wrong_iif()` as well, so both
guards are walked with a valid index throughout the two FreeBSD suites.*

One thing V2 left undone: sec. 4.5 and sec. 4.6 both RECOMMEND a
configuration option to keep accepting these messages from routers that fail
to send Hellos on point-to-point links, disabled by default.  pimd has no
such option, so a peer of that kind is not interoperable.  Adding one means a
`pimd.conf` keyword and its documentation; nobody has asked for it yet.
*Check: sec. 4.5 `doc/rfc7761.txt:2485`, sec. 4.6 `doc/rfc7761.txt:4273`; the
discard rule itself is `doc/rfc7761.txt:2478` and `:4266`.*


Forwarding goes wrong
---------------------

Every entry this section held is fixed.  What was here was the work that
could be done without new state: the SPTbit conditions and the switch onto
the tree, the Register exchanges, the DR gate on local members, the Hello
parser, the group set an RP mismatch used to discard, and the Joins and
Prunes a change of upstream router owes.  What is left below needs state
pimd does not keep.


State machines pimd does not have
---------------------------------

Eight entries this section held are fixed.  M3, the assert winner state,
and M5, the kernel cache an assert used to be gated on, went together: the
assert state is now per interface -- winner address, winner metric and
Assert Timer per (S,G,I) and (\*,G,I), in `struct assert_state`
(`src/mrt.h`), with Actions A1 to A6 in `src/pim_proto.c` -- so the winner
resends before the losers time out, an AssertCancel is both sent and acted
on, and a dead winner is forgotten at its GenID or its Neighbor Liveness
Timer instead of at `Assert_Time`.  M11 followed them: `assert_machine()`
(`src/pim_proto.c`) is one run of one machine, and `receive_pim_assert()`
runs the (S,G) one of sec. 4.6.1 first and the (\*,G) one of sec. 4.6.2
only where that one held no state and did not move, each on its own entry.
Which machine may take a message is the RPT bit's answer now, not the
lookup's.  M13 went with them, and it decided which of the two metrics an
Assert carries in the first place: `JoinDesired(S,G)` is read off the source
specific state sec. 4.5.5 names now -- `joins(S,G)`, kept apart from the
(\*,G) copy every (S,G) is seeded with in `sg_joined_oifs` (`src/mrt.h`), an
IGMPv3 source-specific membership, a directly connected source, or a
Keepalive Timer `switch_shortest_path()` started (`MRTF_KAT`) -- so a router
forwarding off the shared tree keeps SPTbit clear, and `spt-threshold
infinity` keeps it clear for good.  The metric they carry is the routing
table's now as well, so what is left around them is the preference beside it,
M4 below.

M14 was the last of that family: sec. 4.6.1 gates the NoInfo-to-Loser
transition of the (S,G) machine on `AssertTrackingDesired(S,G,I)`, which is
join and membership state, and `assert_machine()` asked instead whether the
interface was still in the entry's outgoing list -- which it never is once an
assert has taken it.  A last hop router held on the shared tree beside one on
the shortest path tree therefore recorded the loss on its (\*,G), which the
winner never refreshes, and the two collided again every `Assert_Time`.  The
state an (S,G) machine with no entry of its own reads is the (\*,G)'s now,
the same entry it already borrows its metric and its olist from, and an
AssertCancel is handed to both machines: the ordering of sec. 4.6.2 says the
(\*,G) machine may run only where the (S,G) one held no state, and a cancel
is the one message that leaves the (S,G) machine by giving the interface
back, with a (\*,G) Loser state behind it that has nothing left to hold.

M9 and M12 went with them.  M9 was the group set of sec. 4.9.5.2 that carries
a (\*,G) Join: `add_jp_entry()` flushed on message size alone, so above
roughly 65 pruned sources the Join and the tail of its (S,G,rpt) Prune list
landed in different packets and a conformant upstream moved every (S,G,rpt)
it held to NoInfo.  The sets already packed are sent first now, so a split
falls between sets, and where one message is not enough for the set the
section's own rule applies -- the numerically smallest N addresses in network
byte order, the rest left out.  M12 was the third term of
`lost_assert(S,G,I)` reaching the wrong olist: pimd computed one per entry and
used it for forwarding and for Join/Prune both, so a router that lost an
assert while forwarding on the shared tree pruned the source whose traffic it
needed to reach the shortest path tree and win the re-election.
`lost_assert()` is sec. 4.6.5's macro as written now, with no SPTbit gate on
the term the Note under it says exists for exactly that phase, and
`lost_assert_rpt()` beside it is the one `calc_oifs()` subtracts; the upstream
machine of sec. 4.5.5 in `join_or_prune()` (`src/pim_proto.c`) reads
`JoinDesired(S,G)` rather than the forwarding olist.  One conservative corner
is left: `JoinDesired(S,G)`'s second half, `inherited_olist(S,G)` while the
Keepalive Timer runs, is still `calc_oifs()`, so its source-specific term
loses an interface to `lost_assert(S,G,rpt)` where sec. 4.1.5 subtracts only
`lost_assert(S,G)`.  Closing that needs the two halves of `inherited_olist()`
told apart, which is M1; `immediate_olist(S,G)`, the half the Note under
sec. 4.6.5 is about, is exact.

M2 is the eighth: the LAN Prune Delay option of sec. 4.3.3 is sent in every
Hello and parsed out of every neighbor's, and `Effective_Propagation_Delay(I)`,
`Effective_Override_Interval(I)` and `J/P_Override_Interval(I)` are computed
from it the way that section computes them -- the defaults wherever one
neighbor on the link omits the option, and otherwise the largest value anyone
advertises, ours included.  The Prune-Pending Timer of sec. 4.5.1 and 4.5.2 is
that interval now, where it used to be `holdtime/3`, 70 seconds for the usual
holdtime and about six hours for a Join asking for 0xffff; it is zero where
pimd has at most one neighbor on the interface, which is the question
`VIFF_POINT_TO_POINT` used to stand in for, and an outgoing interface that
came from a local member no longer goes the other way and disappears with no
override window at all.

The Propagation_Delay pimd advertises is `TIMER_INTERVAL`, 5 seconds, and not
the 0.5 s default, which makes the interval 8 seconds between two pimds rather
than the 3 the table below gives.  That is the lower bound the same section
asks implementers to enforce "to allow for scheduling and processing delays
within their router": pimd builds a triggered Join in `age_routes()` and no
timer here expires off a tick, so its own override can be a whole
`TIMER_INTERVAL` later than `t_override` asked for, and an upstream told to
wait 3 seconds would stop forwarding first -- the "temporary forwarding
outages" the section warns about, and what the old 70-second window used to
hide.  It goes back to 0.5 when T1 below is fixed and the override can be
scheduled inside a tick.  pimd keeps one timer per (entry,
interface), so Prune-Pending is the Expiry Timer lowered to that delay, which
loses nothing -- "for forwarding purposes, the Prune-Pending state functions
exactly like the Join state" -- with `prune_pending_oifs` (`src/mrt.h`) saying
which of the two an expiry came from, so that the PruneEcho sec. 4.5.1 owes
the LAN is sent for a prune and not for a membership that simply ran out.  The
T bit is advertised clear: it offers to disable Join suppression, which pimd
cannot do, so `Suppression_Enabled(I)` is true on every link it is on and the
explicit tracking the bit exists for stays out of reach.  Propagation_Delay
and Override_Interval are constants rather than the configuration sec. 4.3.3
says they SHOULD be; nobody has asked to move them yet.

**M1.  No (S,G,rpt) state at all.**  Sec. 4.5.3, 4.5.6 and 4.5.7 define a
downstream and an upstream (S,G,rpt) machine with their own Expiry,
Prune-Pending and Override timers.  pimd has one (S,G) entry with one
`joined_oifs`/`pruned_oifs` pair and the `MRTF_RP` flag standing in for the RPT
variant, which produces three distinct failures.  A received Prune(S,G,rpt) is
applied to the (S,G) machine (`src/pim_proto.c:2271-2288`), so on a LAN it
cancels an (S,G) Join another router still wants, and the two flap against each
other with a 60-second period; `calc_oifs()` subtracts the one `pruned_oifs`
from the (S,G) olist unconditionally (`src/route.c:869` for the inherited half
and `:878` for the entry's own), which sec. 4.1.5 forbids.  A received
Join(S,G,rpt) matches neither branch of the Join loop (`src/pim_proto.c:2383`
and `:2450`) and is silently ignored, so a downstream
router can never override another router's RPT prune — the one mechanism
sec. 4.5.7 exists to provide.  And pimd never sends a Join(S,G,rpt) either:
`join_or_prune()` can only return PRUNE for an RPbit entry
(`src/pim_proto.c:1521-1529`), so the triggered machine of 4.5.7 has no
implementation.  Note that the *compound* Join(\*,G)+Prune(S,G,rpt) of sec. 4.5.6
is implemented, via `MRTF_RP` entries dragged into the same group set
(`src/route.c:1933-1952`), and is wire-correct; it is the triggered half that is
missing.
*Check: sec. 4.5.3, `doc/rfc7761.txt:2975` (downstream), sec. 4.5.7, `:3983`
(upstream triggered), sec. 4.5.6, `:3927` (the periodic compound message); the
olist rule pimd breaks is sec. 4.1.5, `:1138`, where `prunes(S,G,rpt)`
subtracts from `joins(*,G)` alone and not from `inherited_olist(S,G)` at
`:1142`.  Effort: large.  Test: none.  `shared-lan` in `test/freebsd-lab.sh` is
the topology it needs -- two downstream routers on one segment, one pruning
what the other joined.*

**M4.  The assert metric preference is a configured constant, not the routing
protocol's.**  Sec. 4.6.3 and sec. 4.9.6 both say the metric preference and the
metric are the unicast routing protocol's.  The metric is, now: `struct rpfctl`
(`src/vif.h`) carries MRIB.metric back from every RPF lookup -- the route's
priority out of the netlink reply (`src/netlink.c`), `rmx_metric` out of the
routing socket's (`src/routesock.c`) -- and `set_incoming()` (`src/route.c`)
gives it to the source, leaving `metric` in `pimd.conf` as the fallback for a
kernel that answers neither.  Two routers on a LAN whose routing tables disagree
about the cost of reaching the source, or the RP, now elect on that rather than
on their addresses, and an election follows a route change while it runs:
sec. 4.6.1 leaves the Loser state when "my metric becomes better than the assert
winner's metric", which `age_asserts()` (`src/pim_proto.c`) evaluates once per
pass because the number can now move without pimd doing anything.

The preference is still the configured one, `uv_local_pref`, 101 unless
`distance` says otherwise.  It is the administrative distance of the routing
protocol that provided the route, and the two RPF backends cannot both answer
that question: netlink gives the protocol in `rtm_protocol`, and FreeBSD keeps
the same RTPROT\_\* value in the nexthop's `nh_origin` but exposes it only over
its own netlink, never over the PF\_ROUTE socket `routesock.c` reads.  Mapping
the one that does answer onto the usual distances would have a Linux pimd
advertise 110 for an OSPF route where a FreeBSD one advertises 101 for the same
route, and sec. 4.6.3 compares the preference before it ever looks at the
metric: the election on a mixed LAN would be decided by which operating system
each router runs.  So the field stays configuration, per interface, and a domain
whose routers learn the source through different protocols still has to set
`distance` by hand.

One thing the metric inherits from the same asymmetry, smaller because it is
compared second: an ordinary route has priority 0 on Linux and metric 1 on
FreeBSD, so between two routers that agree on everything else the Linux one
wins.  Both numbers are what their own kernel calls the cost of that route.
*Check: sec. 4.6.3, `doc/rfc7761.txt:5215` for `spt_assert_metric(S,I)`, and
sec. 4.9.6, `:6766`, for the two wire fields.  Effort: medium, and it is a
decision rather than work: an administrative distance has to come from
somewhere both backends can reach, or from configuration as it does today.
Test: step 12 of `shared-lan` in `test/freebsd-lab.sh` covers the half that is
fixed, in both directions -- the two contenders reach the RP at a metric
`route change` sets, and the LAN changes hands when either one is bettered,
which with a constant metric it never did.  That is `routesock.c`; the
netlink half of the same lookup has no assertion anywhere, because no test in
`test/` reads the outcome of an assert election on Linux at all.  The
preference half has none either:
between two pimds it is 101 on both, so `assert-lan` in
`test/freebsd-interop.sh` is where it would be seen, the Arista being the one
router on that wire that advertises its RIB's own numbers.*

**M6.  No secondary address list.**  Sec. 4.3.4 requires the Address List option
whenever an interface has secondary addresses, so that neighbors can map an MRIB
next hop to the primary address a Join must be sent to.  pimd neither sends nor
parses option 24, and both lookups compare against the primary only
(`src/route.c:296-322`, `src/route.c:188-192`).  If the RIB's next hop for a
source or RP is a neighbor's secondary address, pimd logs "NOT A PIM ROUTER",
sets `upstream` to NULL and never joins; conversely a neighbor whose MRIB points
at pimd's alias cannot map it back.  `install_altnet()` currently keeps only the
subnet and mask (`src/config.c:266-289`), so pimd's own secondary addresses have
to be retained before they can be advertised.  This is the `alias` lab topology.
*Check: sec. 4.3.4, `doc/rfc7761.txt:1993`, with the option in sec. 4.3.1,
`:1664`, and its wire format in sec. 4.9.2, `:6167`.  Effort: medium to
large.  Test: none.  `alias` in `test/freebsd-lab.sh` builds the interface this
needs, but asserts the altnet RPF path rather than the Address List option.*

**M7.  The Keepalive Timer is not traffic-driven, and nothing in reach makes
that cost anything.**  Sec. 4.2 sets `KeepaliveTimer(S,G)` from arriving data.
Every write to `entry_timer` is a control-plane event or a kernel upcall;
`check_spt_threshold()` reads the MFC counters and never refreshes the timer,
and under `spt-threshold infinity` it returns before reading them at all
(`src/route.c:1551`).

Measured rather than reasoned about: the `rpt` topology of
`test/freebsd-lab.sh` with `spt-threshold infinity` in all three `pimd.conf`s,
ten minutes of continuous traffic, no entry deleted on any router and no gap in
the receiver's stream.  Three refreshes cover the entries between them, and the
cases they cover are disjoint, so the timer never reaches zero while a source
sends:

- An entry with an oif some neighbour joined is refreshed by that neighbour's
  periodic Join every 60 seconds (`src/pim_proto.c:2411`, `:2476`).  In the run
  above `entry_timer` went back to 210 on the same tick as `jp_timer` wrapping
  to 60, every time.
- The DR and the RP refresh each other over the Register probe loop, also every
  60 seconds: the Null-Register sets the RP's timer (`src/pim_proto.c:1031`) and
  the Register-Stop the DR's, while a registered packet sets it at the DR
  directly (`:1239`), which is the one refresh that is data-driven.  Stopping
  pimd on the last hop router, so that no Join is ever sent again, left this
  loop holding both entries up on its own.
- An entry with an empty oif list has no MFC, so every packet is a cache miss
  and refreshes the timer (`src/route.c:1283`).  That is the path the
  `keepalive` scenario pins, and it costs one upcall per packet for as long as
  the source sends, because pimd installs no negative cache entry (the TODO at
  `src/route.c:1268`).

One shape is left over: a last hop router's (S,G) whose only oif is a local
member, with `spt-threshold interval` longer than 210 seconds, so that the poll
calling `switch_shortest_path()` no longer refreshes it either.  `age_routes()`
then deletes it through the `PIMD_VIFM_LASTHOP_ROUTER` branch
(`src/route.c:2005`) precisely because those leaves are inherited from the
(\*,G) -- which is also why no traffic is lost: the (\*,G) keeps forwarding and
the entry returns at the next poll.  What that costs is the switch to the
shortest path tree oscillating with the period of the poll interval.
*Check: sec. 4.2, `doc/rfc7761.txt:1375` and `:1383`, where arriving data sets
the timer; `Keepalive_Period` is sec. 4.11, `:7136`.  Effort: medium.  Test:
none, and the run above says a lab here would be asserting that the three
masks work rather than that the timer does.*

**M8.  Triggered Joins and Prunes wait for the next tick.**  The transitions in
sec. 4.5.4 and 4.5.5 send immediately.  `change_interfaces()` and its callers
turn every such transition into `FIRE_TIMER(mrt->jp_timer)`
(`src/route.c:979` and `:1040` in `change_interfaces()` itself, `:483`, `:738`,
`:1434` and `:1499` in its callers), and the message is only built when
`age_routes()` next runs, every `TIMER_INTERVAL` = 5 seconds.  `add_leaf()`
and the `MRTF_NEW` arms of `receive_pim_join_prune()` are the exceptions that do
send at once.  Up to 5 seconds of added join latency on every other transition,
including the SPT switchover.  The same code re-arms the Join Timer on the
transition to NotJoined instead of cancelling it, so a pruned entry re-sends its
Prune every 60 seconds instead of once.
*Check: sec. 4.5.4, `doc/rfc7761.txt:3367`, and sec. 4.5.5, `:3618`; every
transition there says "Send" with no delay, and the JoinDesired-goes-FALSE row
at `:3514` and `:3779` cancels the timer rather than re-arming it.  Effort:
medium.  Test: none, and none is obvious: the symptom is up to five seconds of
added latency, which no assertion here could tell from a slow lab.*

Timers
------

Sec. 4.11 values against `src/pimd.h` and friends.  Rows that agree are listed
so the next reader does not re-derive them.  The spec side of the whole table is
sec. 4.11, `doc/rfc7761.txt:6895`, one table per timer name, and sec. 4.10,
`:6804`, lists the timers themselves.

| Spec name | Spec default | pimd | Verdict |
|---|---|---|---|
| Hello\_Period | 30 s | `PIM_TIMER_HELLO_INTERVAL`, settable | ok |
| Triggered\_Hello\_Delay | rand(0, 5 s) | rand(0, 5 s) at boot, immediate on trigger | T3 |
| Default\_Hello\_Holdtime | 105 s | 105 s, sent and used as the NLT fallback | ok |
| J/P\_HoldTime | from message | as received | ok |
| J/P Holdtime sent | 210 s | `PIM_JOIN_PRUNE_HOLDTIME` 210 s | ok |
| t\_periodic | 60 s | `PIM_JOIN_PRUNE_PERIOD` 60 s | ok |
| t\_suppressed | rand(1.1, 1.4) × t\_periodic | 66–84 s | ok |
| Suppression\_Enabled | from the T bit | always on, T advertised clear | ok in effect |
| t\_override | rand(0, Eff. Override) | 0–2 s integer, on a 5 s tick | T1 |
| Propagation\_Delay | 0.5 s | 5000 ms, advertised and negotiated | deliberate, T1 |
| Override\_Interval | 2.5 s | 2500 ms, advertised and negotiated | ok |
| J/P\_Override\_Interval (PPT) | 3 s | the negotiated sum, 8 s between pimds | ok |
| Assert\_Time | 180 s | `PIM_ASSERT_TIMEOUT` 180 s | ok |
| Assert\_Override\_Interval | 3 s | 5 s, the TIMER\_INTERVAL floor | minor |
| Register\_Suppression\_Time | 60 s | 60 s | ok |
| Register\_Probe\_Time | 5 s | 5 s | ok |
| RST(S,G) | 25–85 s | 30–90 s, the probe-time term omitted | minor |
| Keepalive\_Period | 210 s | `PIM_DATA_TIMEOUT` 210 s | M7 |
| RP\_Keepalive\_Period | 185 s | 210 s, i.e. max(210, 185) | ok in effect |

`TIMER_INTERVAL` is 5 seconds and `SET_TIMER`/`IF_TIMEOUT` count whole seconds,
so no sub-5-second spec value is representable today.  That is the real cost
behind T1 and M8, and behind the one minor assert row: the winner's timer is
`PIM_ASSERT_WINNER_TIMEOUT`, `Assert_Time - Assert_Override_Interval` rounded
down to whole ticks, so 175 s rather than 177 s.  A timer only ever expires on
a tick, and 177 and 180 reach zero on the same one, which would have the
resend race the refresh it exists to deliver.  The effect is a 5-second
override interval where the spec asks for 3, which is the direction that is
safe.

**T1.  `t_override` cannot be expressed on a 5-second tick.**
The interval is the link's now, `effective_override_interval()`
(`src/pim_proto.c`) rather than a constant, and no longer RFC 2362's
`[Random-Delay-Join-Timeout]` of 4.5, which is a different quantity.  What is
left is the quantization: `jp_override_timeout()` divides milliseconds into
whole seconds and yields 0, 1 or 2 of them at the default 2500, and the timer
only fires on the next 5-second tick, so the delay is effectively the tick
phase and the randomization does nothing.  An override Join can therefore
arrive about 5 seconds after the Prune it must cancel, against an upstream --
pimd included, now that the Prune-Pending Timer is the interval sec. 4.11
asks for -- that deleted the oif after 3.
*Check: the `t_override` row of sec. 4.11, `doc/rfc7761.txt:7077`, and
`Effective_Override_Interval(I)` in sec. 4.3.3, `:1925`.  Effort: medium; it
is sub-tick scheduling, which nothing in `timer.c` has today.  Test: none.  It
needs a shared LAN and an oif deleted after 3 seconds where the override
arrives at 5, which any two pimds on one segment now have: `shared-lan` in
`test/freebsd-lab.sh` and `assert-lan` in `test/freebsd-interop.sh` both
build it.*

**T2.  (\*,G) Join suppression is inert.**  The interval itself is the spec's
now -- `jp_suppression_timeout()` (`src/pim_proto.c`) draws 66 to 84 seconds,
where the old range started at `t_periodic` exactly and let a suppressed router
send inside the very period it was suppressed for.  The (\*,G) branch still
computes its guards and then falls through with no `SET_TIMER` at all, three
tests followed by a bare `continue` (`src/pim_proto.c:2027-2040`).  The
assignment was deleted in `892acbe`, "Fix random loss of multicast, lasts 5-10
mins, by Ventus Networks", as a workaround, so every router on a LAN sends its
own periodic Join(\*,G).  The effect is control-plane noise rather than lost
traffic, which is why it was tolerable, but restoring it needs the original
loss scenario reproduced first: the bug it papers over is most likely in
`join_or_prune()` or the `jp_timer` accounting.  Note also the address tiebreak
in those guards has no counterpart in RFC 7761.
*Check: the `t_suppressed` row of sec. 4.11, `doc/rfc7761.txt:7070`; the "See
Join(\*,G) to RPF'(\*,G)" transition that arms it is sec. 4.5.4, `:3543`, and
its (S,G) twin sec. 4.5.5, `:3815`.  Effort: medium -- the change is one
assignment, reproducing what it broke is the work.  Test: none.  Join
suppression needs two routers wanting the same group on one segment, which
`shared-lan` and `assert-lan` both have.*

**T3.  The triggered Hello answering a new neighbor is not delayed.**  The
startup half is done: `start_vif()` (`src/vif.c`) arms `uv_hello_timer` with
rand(0, `PIM_TRIGGERED_HELLO_DELAY`) and no longer sends a Hello itself, so
the randomized value survives instead of being overwritten by
`send_pim_hello()` before the first tick.  The Hello that answers a new or
rebooted neighbor (`src/pim_proto.c:280`) is still sent at once rather than
after rand(0, 5 s), so a whole LAN answers a rebooting router in the same
instant and then converges onto its clock.

That one is deliberate for now, and moving it needs a second timer rather than
a delay: sec. 3.5 of RFC 5059 has the DR unicast a Bootstrap to the new
neighbor immediately afterwards (`src/pim_proto.c:287`), and
`receive_pim_bootstrap()` drops a Bootstrap from a router it has had no Hello
from.  Delaying the Hello on the existing `uv_hello_timer` would have us send
that Bootstrap into a peer that discards it.
*Check: sec. 4.3.1, `doc/rfc7761.txt:1670` (the triggered Hello answering a new
neighbor); the value is the `Triggered_Hello_Delay` row of sec. 4.11, `:6958`.
Effort: medium; a per-vif triggered-Hello timer, separate from the periodic
one, and the RFC 5059 Bootstrap has to wait for it.  Test: none; it is startup
timing, and every lab here starts its routers together.*


Interop details
---------------

Both entries this section held are fixed: I1, the Null-Register dummy IP
header that named protocol 17 where sec. 4.9.3 wants 103, and I2, the ECN
bits and DSCP that sec. 4.4.1 has a Register copy from the packet it
encapsulates.  The section stays so the next reader knows the two were
looked at rather than missed: both are one-directional, and neither shows
up between two pimds, which is why they sat here.  `arista-rp` in
`test/freebsd-interop.sh` is where an RP written by somebody else reads
what we send.
*Check: sec. 4.9.3, `doc/rfc7761.txt:6253` for the dummy header, the `IP
Protocol` row at `:6269`; sec. 4.4.1, `:2291` (ECN) and `:2303` (DSCP), with
the RP's side of the same copy at sec. 4.4.2, `:2443` and `:2446`.*


Checked, no action
------------------

- **The Border bit is already compliant.**  Sec. 4.9.3 deprecates it: set 0 on
  transmission, ignore on reception, which is what the code does.  The
  outstanding TODO at `src/pim_proto.c:891-895` describes RFC 2362 PMBR
  behaviour and has no code behind it; with (\*,\*,RP) and PMBR removed from this
  tree the right change is deleting the comment.  *Check: sec. 4.9.3,
  `doc/rfc7761.txt:6233`.*
- **Register-Stop rate limiting is not an RFC requirement.**  Sec. 4.4.2
  prescribes one Register-Stop per qualifying Register and no rate limit; the
  DR's suppression timer is the pacing mechanism.  The TODO at
  `src/pim_proto.c:1424` can go.  Its security dimension is real but belongs to
  V3.  *Check: sec. 4.4.2, `doc/rfc7761.txt:2364` for the pseudocode and `:2402`
  for its Note (\*).*
- **(\*,\*,RP) group sets are skipped, which is what RFC 7761 wants.**  The
  promise of a second pass in the comment at `src/pim_proto.c:2181-2182` is
  stale — there is no second pass — but the resulting behaviour is correct.  The
  suppression half of the same function still has live (\*,\*,RP) handling, and
  `pack_and_send_jp_message()` can still encode such a group set, though no
  caller asks it to.  *Check: Appendix A, `doc/rfc7761.txt:7567`, which is where
  RFC 4601's (\*,\*,RP) support was removed.*
- **Sec. 4.5.6's compound Join(\*,G)+Prune(S,G,rpt) is implemented**, through
  `MRTF_RP` entries pulled into the same group set (`src/route.c:1933-1952`) and
  the RPT bit set from that flag.  What is missing around it is M1, not this.  *Check: sec. 4.5.6, `doc/rfc7761.txt:3927`.*
- **The RP's decapsulate-and-forward step is the kernel's**, via `MRT_PIM` and
  the register vif, which is the literal reading of sec. 4.4.2's note that
  implementations should not make it a special case.  One consequence worth
  knowing: register-vif creation is a hard dependency of RP function, not only
  of DR function.  *Check: sec. 4.4.2, Note (+) at `doc/rfc7761.txt:2420`.*
- **`oiflist (-) iif` happens inside `k_chg_mfc()`** (`src/kern.c:466-471`), not
  in `calc_oifs()` where the comment promises it.  The forwarding result is
  right, but `mrt->oifs` is consequently not a pure function of the join/prune
  state — whether it still contains its own iif depends on which caller last ran
  — and two "did this arrive on an oif?" tests read it
  (`src/route.c:1441`, `src/pim_proto.c:3669`).  *Check: sec. 4.2,
  `doc/rfc7761.txt:1425`, where `oiflist = oiflist (-) iif` is a step of the
  forwarding rules and not part of the olist macros of sec. 4.1.5, `:1131`.*
- **`lost_assert()` is already enforced for local members.**  `calc_oifs()`
  (`src/route.c`) merges `leaves` into the outgoing interfaces and subtracts
  `asserted_oifs` immediately after, so an assert loser does not forward to
  its local members even though the leaf bit stays set in `mrt->leaves`.  The
  bit is IGMP state, not a forwarding decision; read the order in
  `calc_oifs()` before concluding otherwise.
- **`rpentry->mrtlink` is always NULL.**  The only write to any `mrtlink` is
  `grp->mrtlink` in `insert_grpmrtlink()` (`src/mrt.c:732`), so with (\*,\*,RP)
  gone nothing hangs an entry off an RP entry any more.  The blocks that read
  `rp->mrtlink` — in `delete_pim_nbr()` and in `find_route()` — are dead.  This
  is also what makes the V4 sweep over `grplist` complete: every live
  `mrtentry_t` is either a group's `grp_route` or on its `mrtlink`.
- **`send_periodic_pim_join_prune()` is dead code.**  Its only caller is inside
  `#ifdef TOBE_DELETED` (`src/vif.c:946-958`).  All Join/Prune generation happens
  in `age_routes()` and `send_pim_join()`.  Worth knowing before reading it as
  the periodic sender it is named after.
