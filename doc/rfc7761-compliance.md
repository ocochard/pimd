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
unasserted, so that it flips to `ok` the day it is fixed.  Four are carried
that way, and three of them report `ok`, so they stay as tripwires against the
deviation coming back: the assert RPT-bit entry of 4.6.1 in `shared-lan-spt`,
the SPTbit entry of 4.2.2 in `assert-lan`, and the assert winner state of
4.6.1 and 4.6.2, which `assert-lan` asserts from both sides.  The fourth is
M14, and it depends on the order its scenario runs in: `KNOWN` where the
sub-case runs on its own, `ok` in the full walk.  Read its `Test:` note before
reading anything into either.

Every entry therefore ends with a `Test:` note saying what reproduces it, and
most of them say `none` -- the point of writing it down is that the gap is
visible from this list rather than only from grepping the labs.  M14 is the
only one a test reproduces at all.  Where an entry names a scenario without
asserting anything, it is because that scenario builds the topology the
deviation needs and stops short of the assertion; those are the cheap ones to
close.  Several are not blackbox-testable at all, and say so: a five-second
latency or a startup race cannot be told from a slow lab.


Input validation and trust
--------------------------

Every entry this section held is fixed: V1, an unbounded parse in
`receive_pim_register_stop()`; V2, Join/Prune and Assert accepted from any
host on the subnet; V3, a Register creating routing state before the
I\_am\_RP test; and V4, a freed neighbor left in `mrt->upstream` by an
assert.  The section stays, and keeps its numbering, because these are the
entries where a compliance gap was also a way in, and the next reader should
know they were looked for rather than wonder.

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

Four entries this section held are fixed.  M3, the assert winner state,
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
M4 below, and the half of M12 that is not a metric at all.

**M1.  No (S,G,rpt) state at all.**  Sec. 4.5.3, 4.5.6 and 4.5.7 define a
downstream and an upstream (S,G,rpt) machine with their own Expiry,
Prune-Pending and Override timers.  pimd has one (S,G) entry with one
`joined_oifs`/`pruned_oifs` pair and the `MRTF_RP` flag standing in for the RPT
variant, which produces three distinct failures.  A received Prune(S,G,rpt) is
applied to the (S,G) machine (`src/pim_proto.c:2049-2074`), so on a LAN it
cancels an (S,G) Join another router still wants, and the two flap against each
other with a 60-second period; `calc_oifs()` subtracts the one `pruned_oifs`
from the (S,G) olist unconditionally (`src/route.c:847` for the inherited half
and `:856` for the entry's own), which sec. 4.1.5 forbids.  A received
Join(S,G,rpt) matches neither branch of the Join loop (`src/pim_proto.c:2175`
and `:2239`) and is silently ignored, so a downstream
router can never override another router's RPT prune — the one mechanism
sec. 4.5.7 exists to provide.  And pimd never sends a Join(S,G,rpt) either:
`join_or_prune()` can only return PRUNE for an RPbit entry
(`src/pim_proto.c:1389-1397`), so the triggered machine of 4.5.7 has no
implementation.  Note that the *compound* Join(\*,G)+Prune(S,G,rpt) of sec. 4.5.6
is implemented, via `MRTF_RP` entries dragged into the same group set
(`src/route.c:1859-1908`), and is wire-correct; it is the triggered half that is
missing.
*Check: sec. 4.5.3, `doc/rfc7761.txt:2975` (downstream), sec. 4.5.7, `:3983`
(upstream triggered), sec. 4.5.6, `:3927` (the periodic compound message); the
olist rule pimd breaks is sec. 4.1.5, `:1138`, where `prunes(S,G,rpt)`
subtracts from `joins(*,G)` alone and not from `inherited_olist(S,G)` at
`:1142`.  Effort: large.  Test: none.  `shared-lan` in `test/freebsd-lab.sh` is
the topology it needs -- two downstream routers on one segment, one pruning
what the other joined.*

**M2.  No LAN Prune Delay option, and no real Prune-Pending timer.**
Sec. 4.3.3 wants the option in every Hello on a multi-access LAN, and
`Effective_Propagation_Delay`/`Effective_Override_Interval` derived from the
largest value any neighbor advertises; sec. 4.5.1 and 4.5.2 start a Prune-Pending
Timer of `J/P_Override_Interval(I)`, or zero when there is only one neighbor on
the interface.  pimd neither sends nor parses option type 2
(`src/pim_proto.c:745-755` and `:681-706`), keeps none of the four values, and
has no Prune-Pending state: it lowers the *Expiry* timer to
`vif_deletion_delay[vifi]`, whose only assignment is `holdtime/3`
(`src/pim_proto.c:2199`, `:2261`), 70 seconds for the usual 210-second holdtime.
The single-neighbor case is approximated by `VIFF_POINT_TO_POINT`, which is not
the same question.  So a Prune on a shared LAN leaves traffic flowing for 70
seconds instead of 3, compounding per hop; a Join with holdtime 0xffff sets the
delay to 21845 seconds, about six hours.  Where `vif_deletion_delay` is still 0,
because the oif came from a local leaf rather than from a received Join, the same
code drops the oif instantly with no override window at all.  No PruneEcho is
sent either, so a Prune lost on the LAN is never recovered.
*Check: sec. 4.3.3, `doc/rfc7761.txt:1812`, with the option itself in sec.
4.3.1, `:1657`, and its wire format in sec. 4.9.2, `:6083`; the Prune-Pending
Timer is sec. 4.5.1, `:2674`, and sec. 4.5.2, `:2899`;
`J/P_Override_Interval(I)` is sec. 4.11, `:7013`.  Effort: large, though
emitting the option with default values so neighbors stop falling back is
small.  Test: none, and `assert-lan` in `test/freebsd-interop.sh` is where it
becomes visible: the Arista advertises the LAN Prune Delay option pimd neither
sends nor parses, so those values are already on that wire waiting to be
asserted on.*

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
(`src/route.c:1509`).

Measured rather than reasoned about: the `rpt` topology of
`test/freebsd-lab.sh` with `spt-threshold infinity` in all three `pimd.conf`s,
ten minutes of continuous traffic, no entry deleted on any router and no gap in
the receiver's stream.  Three refreshes cover the entries between them, and the
cases they cover are disjoint, so the timer never reaches zero while a source
sends:

- An entry with an oif some neighbour joined is refreshed by that neighbour's
  periodic Join every 60 seconds (`src/pim_proto.c:2202`, `:2264`).  In the run
  above `entry_timer` went back to 210 on the same tick as `jp_timer` wrapping
  to 60, every time.
- The DR and the RP refresh each other over the Register probe loop, also every
  60 seconds: the Null-Register sets the RP's timer (`src/pim_proto.c:937`) and
  the Register-Stop the DR's, while a registered packet sets it at the DR
  directly (`:1116`), which is the one refresh that is data-driven.  Stopping
  pimd on the last hop router, so that no Join is ever sent again, left this
  loop holding both entries up on its own.
- An entry with an empty oif list has no MFC, so every packet is a cache miss
  and refreshes the timer (`src/route.c:1250`).  That is the path the
  `keepalive` scenario pins, and it costs one upcall per packet for as long as
  the source sends, because pimd installs no negative cache entry (the TODO at
  `src/route.c:1234`).

One shape is left over: a last hop router's (S,G) whose only oif is a local
member, with `spt-threshold interval` longer than 210 seconds, so that the poll
calling `switch_shortest_path()` no longer refreshes it either.  `age_routes()`
then deletes it through the `PIMD_VIFM_LASTHOP_ROUTER` branch
(`src/route.c:1961`) precisely because those leaves are inherited from the
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
(`src/route.c:957` and `:1018` in `change_interfaces()` itself, `:483`, `:721`,
`:1392` and `:1457` in its callers), and the message is only built when
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

**M9.  A group set carrying a (\*,G) Join can be split across messages.**
Sec. 4.9.5.2 makes that list of (S,G,rpt) Prunes unsplittable and, when they do
not fit, requires the numerically smallest N.  `add_jp_entry()` flushes on size
alone (`src/pim_proto.c:2553-2560`), with no notion of the group set it is in the
middle of and no ordering of the sources.  Above roughly 65 pruned sources the
Join(\*,G) and the tail of its prune list land in different packets, and a
conformant upstream moves every (S,G,rpt) it holds to NoInfo on the first one —
a burst of duplicate traffic on the shared tree once per period, every period.
*Check: sec. 4.9.5.2, `doc/rfc7761.txt:6684`; "MUST NOT be split" at `:6698`
and the smallest-N rule at `:6706`.  Effort: medium.  Test: none; it needs a
group with more than about 65 pruned sources, which no scenario builds.*

**M12.  `lost_assert(S,G,I)`'s third term reaches the olist, not the Join.**
Sec. 4.6.5 makes that test three terms: assert state on the interface, a
winner that is not us, and the winner's metric being better than
`spt_assert_metric(S,I)`.  The third one is computed now, in `lost_assert()`
(`src/pim_proto.c`), and `calc_oifs()` (`src/route.c`) asks it per interface
rather than subtracting `asserted_oifs` whole: an entry on the shortest path
tree takes back an interface it lost to a winner whose metric no longer
beats the one it would assert with from that tree.  Until SPTbit is set the
answer is `lost_assert(S,G,rpt,I)`, plain assert state, because sec. 4.2
forwards off `inherited_olist(S,G,rpt)` until then.

What the term is really for is the other olist, and that half is missing.
Sec. 4.1.5 keeps `immediate_olist(S,G)` -- `joins(S,G)` and
`pim_include(S,G)` minus `lost_assert(S,G)` -- apart from the inherited one,
and `JoinDesired(S,G)` is read off that, or off `inherited_olist(S,G)` while
the Keepalive Timer runs: both of them carry the term, and neither is the
olist sec. 4.2 forwards off while SPTbit is clear.  A router that loses an
assert while forwarding on the shared tree, to a winner it would beat from
the shortest path tree, is meant to keep its (S,G) Join on that strength
alone, get traffic, set SPTbit and win the re-election.  pimd computes one
olist per entry and uses it for forwarding and for Join/Prune both, so that
router prunes the source whose traffic it needs to get there, and the two
never resolve -- the deadlock the Note under the macro describes.  Closing it
means keeping the two olists apart, not adding another term, and half of that
is in place: `join_desired()` (`src/route.c`) builds `immediate_olist(S,G)`
out of `sg_joined_oifs`, the `joins(S,G)` an (S,G) entry does not inherit
from its (\*,G), and sec. 4.2.2 is read off it.  What still has one olist for
forwarding and for Join/Prune both is `join_or_prune()` (`src/pim_proto.c`),
which is where the deadlock is.
*Check: sec. 4.6.5, `doc/rfc7761.txt:5294`, with the Note at `:5305`;
`spt_assert_metric(S,I)` is sec. 4.6.3, `:5215`; the two olists are sec.
4.1.5, `:1131`, and `JoinDesired(S,G)` sec. 4.5.5, `:3738`.  Effort: medium.
Test: none.  It needs a router that loses an assert while forwarding on the
shared tree to one it would beat from the shortest path tree, so the two
metrics have to differ: `route change -metric` does that between two pimds
now, the way step 12 of `shared-lan` in `test/freebsd-lab.sh` does it, and
`shared-lan-spt` is the scenario that already gets one of the two onto the
shortest path tree.*

**M14.  An Assert the (S,G) machine should take is unreachable once the
shared tree has lost the interface.**  Sec. 4.6.1 gates the NoInfo-to-Loser
transition of the (S,G) machine on `AssertTrackingDesired(S,G,I)`, which is
join and membership state -- `joins(*,G)` on I is enough -- and says nothing
about the outgoing interfaces.  `assert_machine()` (`src/pim_proto.c`) asks
instead whether the interface is still in the entry's `oifs`, or whether the
entry the state lives on has already lost it; a router with no (S,G) entry
yet has no such entry, and the (*,G) it borrows its metric from has just lost
the interface, so the message reaches neither machine's NoInfo and the (*,G)
machine's Loser state answers it instead.

A last hop router held on the shared tree beside a router that is on the
shortest path tree is exactly that case, and it keeps no `AssertWinner(S,G,I)`
for the LAN: `lost_assert(S,G,rpt,I)` of sec. 4.6.5 reads NULL and what holds
the interface is the (*,G) state alone.  That state is not refreshed, because
the winner asserts per source from then on, and the downstream router that
would clear it with a Join(*,G) now sends that Join to the winner instead.
So the interface comes back at `Assert_Time`, the two routers collide, and the
election runs again every 180 seconds.
*Check: sec. 4.6.1, `doc/rfc7761.txt:4279`, with
`AssertTrackingDesired(S,G,I)` at `:4431` and the transition it gates at
`:4519`; `lost_assert(S,G,rpt,I)` is sec. 4.6.5, `:5284`; the AssertCancel is
sec. 4.6.4, `:5245`.  Effort: small, but not the one-line widening of the
`oifs` test it looks like -- that was measured, and it hands the (S,G) machine the AssertCancel of sec. 4.6.4 as
well, which then clears the (S,G) state and returns, leaving the (*,G) Loser
state holding the interface for the full `Assert_Time`: `assert-lan` reports
the AssertCancel case as a known deviation the moment it is done that way.
Both machines have to answer the cancel for that to hold together.  Test: the
`rpt-bit` sub-case of `assert-lan` in `test/freebsd-interop.sh` goes on asking
for the loss on the (S,G) and reports `KNOWN` through `xfail()` while it lands
on the (*,G) instead -- but only when that sub-case is run on its own,
`AL_CASES=rpt-bit`.  In the full walk it reports `ok`: the Arista has three
elections behind it by then and its (S,G) Assert reaches R3 before the (*,G)
one has taken the interface away, so the (S,G) machine is still reachable and
takes it.  Which of the two orderings a run saw is worth checking before
reading anything into either.*


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
| Suppression\_Enabled | from the T bit | always on | M2 |
| t\_override | rand(0, 2.5 s) | 0–2 s integer, on a 5 s tick | T1 |
| Propagation\_Delay | 0.5 s | not tracked | M2 |
| Override\_Interval | 2.5 s | not tracked, not advertised | M2 |
| J/P\_Override\_Interval (PPT) | 3 s | `holdtime/3`, 70 s | M2 |
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
The constant is the spec's now, `PIM_OVERRIDE_INTERVAL` 2.5 (`src/pimd.h`),
and no longer RFC 2362's `[Random-Delay-Join-Timeout]` of 4.5, which is a
different quantity.  What is left is the quantization:
`(RANDOM() % (int)(10 * 2.5)) / 10` in `jp_override_timeout()`
(`src/pim_proto.c`) yields 0, 1 or 2 whole seconds, and the timer only fires
on the next 5-second tick, so the delay is effectively the tick phase and the
randomization does nothing.  An override Join can therefore arrive about 5
seconds after the Prune it must cancel, against a conformant upstream that
deleted the oif after 3.  Against another pimd it is masked by M2.
*Check: the `t_override` row of sec. 4.11, `doc/rfc7761.txt:7077`, and
`Effective_Override_Interval(I)` in sec. 4.3.3, `:1925`.  Effort: medium; it
is sub-tick scheduling, which nothing in `timer.c` has today.  Test: none.  It
needs a shared LAN and a peer that deletes the oif after 3 seconds rather than
pimd's 5, so `assert-lan` in `test/freebsd-interop.sh` is the natural home.*

**T2.  (\*,G) Join suppression is inert.**  The interval itself is the spec's
now -- `jp_suppression_timeout()` (`src/pim_proto.c`) draws 66 to 84 seconds,
where the old range started at `t_periodic` exactly and let a suppressed router
send inside the very period it was suppressed for.  The (\*,G) branch still
computes its guards and then falls through with no `SET_TIMER` at all, three
tests followed by a bare `continue` (`src/pim_proto.c:1797-1808`).  The
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
rebooted neighbor (`src/pim_proto.c:270`) is still sent at once rather than
after rand(0, 5 s), so a whole LAN answers a rebooting router in the same
instant and then converges onto its clock.

That one is deliberate for now, and moving it needs a second timer rather than
a delay: sec. 3.5 of RFC 5059 has the DR unicast a Bootstrap to the new
neighbor immediately afterwards (`src/pim_proto.c:277`), and
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
  outstanding TODO at `src/pim_proto.c:768-772` describes RFC 2362 PMBR
  behaviour and has no code behind it; with (\*,\*,RP) and PMBR removed from this
  tree the right change is deleting the comment.  *Check: sec. 4.9.3,
  `doc/rfc7761.txt:6233`.*
- **Register-Stop rate limiting is not an RFC requirement.**  Sec. 4.4.2
  prescribes one Register-Stop per qualifying Register and no rate limit; the
  DR's suppression timer is the pacing mechanism.  The TODO at
  `src/pim_proto.c:1301` can go.  Its security dimension is real but belongs to
  V3.  *Check: sec. 4.4.2, `doc/rfc7761.txt:2364` for the pseudocode and `:2402`
  for its Note (\*).*
- **(\*,\*,RP) group sets are skipped, which is what RFC 7761 wants.**  The
  promise of a second pass in the comment at `src/pim_proto.c:1949-1950` is
  stale — there is no second pass — but the resulting behaviour is correct.  The
  suppression half of the same function still has live (\*,\*,RP) handling, and
  `pack_and_send_jp_message()` can still encode such a group set, though no
  caller asks it to.  *Check: Appendix A, `doc/rfc7761.txt:7567`, which is where
  RFC 4601's (\*,\*,RP) support was removed.*
- **Sec. 4.5.6's compound Join(\*,G)+Prune(S,G,rpt) is implemented**, through
  `MRTF_RP` entries pulled into the same group set (`src/route.c:1859-1908`) and
  the RPT bit set from that flag.  What is missing around it is M1 and M9, not
  this.  *Check: sec. 4.5.6, `doc/rfc7761.txt:3927`.*
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
  (`src/route.c:1399`, `src/pim_proto.c:3295`).  *Check: sec. 4.2,
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
