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
unasserted, so that it flips to `ok` the day it is fixed.  Three are carried
that way and all three now report `ok`, so they stay as tripwires against the
deviation coming back: the assert RPT-bit entry of 4.6.1 in `shared-lan-spt`,
the SPTbit entry of 4.2.2 in `assert-lan`, and the assert winner state of
4.6.1 and 4.6.2, which `assert-lan` asserts from both sides.

Every entry therefore ends with a `Test:` note saying what reproduces it, and
most of them say `none` -- the point of writing it down is that the gap is
visible from this list rather than only from grepping the labs.  Nothing here
is carried as a live `xfail()` today.  Where an entry names a scenario without
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

Two entries this section held are fixed.  M3, the assert winner state, and
M5, the kernel cache an assert used to be gated on, went together: the
assert state is now per interface -- winner address, winner metric and
Assert Timer per (S,G,I) and (\*,G,I), in `struct assert_state`
(`src/mrt.h`), with Actions A1 to A6 in `src/pim_proto.c` -- so the winner
resends before the losers time out, an AssertCancel is both sent and acted
on, and a dead winner is forgotten at its GenID or its Neighbor Liveness
Timer instead of at `Assert_Time`.  What is left around them is M4 below,
the metric they carry, and M11, the fact that there is one machine where
sec. 4.6 defines two.

**M1.  No (S,G,rpt) state at all.**  Sec. 4.5.3, 4.5.6 and 4.5.7 define a
downstream and an upstream (S,G,rpt) machine with their own Expiry,
Prune-Pending and Override timers.  pimd has one (S,G) entry with one
`joined_oifs`/`pruned_oifs` pair and the `MRTF_RP` flag standing in for the RPT
variant, which produces three distinct failures.  A received Prune(S,G,rpt) is
applied to the (S,G) machine (`src/pim_proto.c:1783-1807`), so on a LAN it
cancels an (S,G) Join another router still wants, and the two flap against each
other with a 60-second period; `calc_oifs()` subtracts the one `pruned_oifs`
from the (S,G) olist unconditionally (`src/route.c:519-522`), which sec. 4.1.5
forbids.  A received Join(S,G,rpt) matches neither branch of the Join loop
(`src/pim_proto.c:1908` and `:1973`) and is silently ignored, so a downstream
router can never override another router's RPT prune — the one mechanism
sec. 4.5.7 exists to provide.  And pimd never sends a Join(S,G,rpt) either:
`join_or_prune()` can only return PRUNE for an RPbit entry
(`src/pim_proto.c:1126-1155`), so the triggered machine of 4.5.7 has no
implementation.  Note that the *compound* Join(\*,G)+Prune(S,G,rpt) of sec. 4.5.6
is implemented, via `MRTF_RP` entries dragged into the same group set
(`src/route.c:1454-1502`), and is wire-correct; it is the triggered half that is
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
(`src/pim_proto.c:592-602` and `:538-561`), keeps none of the four values, and
has no Prune-Pending state: it lowers the *Expiry* timer to
`vif_deletion_delay[vifi]`, whose only assignment is `holdtime/3`
(`src/pim_proto.c:1924`, `:1989`), 70 seconds for the usual 210-second holdtime.
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

**M4.  Assert metrics are configured constants, not MRIB metrics.**  Sec. 4.6.3
and sec. 4.9.6 both say the metric preference and metric are the unicast
routing protocol's.  `set_incoming()` assigns the per-interface
`uv_local_pref`/`uv_local_metric` to every source that is not directly connected
(`src/route.c:267-270`), defaulting to 101 and 1024; `struct rpfctl`
(`src/vif.h:318-322`) carries no room for anything else.  Every pimd on a LAN
therefore advertises the same metric and `compare_metrics()` always falls through
to the address tiebreak, so the highest-IP router wins every assert regardless of
its distance to the source, and traffic is pulled onto the long path.  The
`distance`/`metric` settings in `pimd.conf` are the only lever.  This answers the
old TODO question about whether asserts on the iif are evaluated with the right
metrics: they are compared correctly, but the numbers being compared are
constants.
*Check: sec. 4.6.3, `doc/rfc7761.txt:5215` for `spt_assert_metric(S,I)`, and
sec. 4.9.6, `:6766`, for the two wire fields.  Effort: large; it needs
`k_req_incoming()` and `struct rpfctl` to carry preference and metric in both
`netlink.c` and `routesock.c`.  Test: no assertion, but `assert-lan` in
`test/freebsd-interop.sh` is built on it -- the Arista advertises its RIB
metrics, so that LAN is the only place pimd's constants are ever compared
against anything else, and its sub-cases drive the election by each field of
sec. 4.6.3 in turn.  Asserting the deviation itself needs pimd's advertised
metric to follow a route change, which needs a routing daemon in the lab.*

**M6.  No secondary address list.**  Sec. 4.3.4 requires the Address List option
whenever an interface has secondary addresses, so that neighbors can map an MRIB
next hop to the primary address a Join must be sent to.  pimd neither sends nor
parses option 24, and both lookups compare against the primary only
(`src/route.c:276-298`, `src/route.c:188-192`).  If the RIB's next hop for a
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
(`src/route.c:1385`).

Measured rather than reasoned about: the `rpt` topology of
`test/freebsd-lab.sh` with `spt-threshold infinity` in all three `pimd.conf`s,
ten minutes of continuous traffic, no entry deleted on any router and no gap in
the receiver's stream.  Three refreshes cover the entries between them, and the
cases they cover are disjoint, so the timer never reaches zero while a source
sends:

- An entry with an oif some neighbour joined is refreshed by that neighbour's
  periodic Join every 60 seconds (`src/pim_proto.c:2159`, `:2217`).  In the run
  above `entry_timer` went back to 210 on the same tick as `jp_timer` wrapping
  to 60, every time.
- The DR and the RP refresh each other over the Register probe loop, also every
  60 seconds: the Null-Register sets the RP's timer (`src/pim_proto.c:891`) and
  the Register-Stop the DR's, while a registered packet sets it at the DR
  directly (`:1081`), which is the one refresh that is data-driven.  Stopping
  pimd on the last hop router, so that no Join is ever sent again, left this
  loop holding both entries up on its own.
- An entry with an empty oif list has no MFC, so every packet is a cache miss
  and refreshes the timer (`src/route.c:1134`).  That is the path the
  `keepalive` scenario pins, and it costs one upcall per packet for as long as
  the source sends, because pimd installs no negative cache entry (the TODO at
  `src/route.c:1117`).

One shape is left over: a last hop router's (S,G) whose only oif is a local
member, with `spt-threshold interval` longer than 210 seconds, so that the poll
calling `switch_shortest_path()` no longer refreshes it either.  `age_routes()`
then deletes it through the `PIMD_VIFM_LASTHOP_ROUTER` branch
(`src/route.c:1823`) precisely because those leaves are inherited from the
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
(`src/route.c:608-610`, `:460`, `:1066`, `:1009`), and the message is only built
when `age_routes()` next runs, every `TIMER_INTERVAL` = 5 seconds.  `add_leaf()`
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
alone (`src/pim_proto.c:2249-2256`), with no notion of the group set it is in the
middle of and no ordering of the sources.  Above roughly 65 pruned sources the
Join(\*,G) and the tail of its prune list land in different packets, and a
conformant upstream moves every (S,G,rpt) it holds to NoInfo on the first one —
a burst of duplicate traffic on the shared tree once per period, every period.
*Check: sec. 4.9.5.2, `doc/rfc7761.txt:6684`; "MUST NOT be split" at `:6698`
and the smallest-N rule at `:6706`.  Effort: medium.  Test: none; it needs a
group with more than about 65 pruned sources, which no scenario builds.*

**M11.  One assert state machine where sec. 4.6 defines two.**  Sec. 4.6.1
and sec. 4.6.2 are separate machines, an (S,G) one and a (\*,G) one, run in
that order: no transition may occur in the (\*,G) machine unless the (S,G)
machine is in NoInfo both before and after the message, and none at all if
the message moved the (S,G) machine.  `receive_pim_assert()` picks one
entry instead -- the longest match, preferring one with a kernel cache
(`src/pim_proto.c`) -- and runs a single election on it, so a router holding
both (S,G) and (\*,G) state for a group can keep assert state for only one
of them per interface.  Where the two machines would disagree, which is the
case sec. 4.6.2 spells out at length, pimd answers with whichever entry the
lookup happened to return.  The same merge is why `lost_assert(S,G,I)` is a
plain bit in `asserted_oifs` rather than the sec. 4.6.5 test, which also
asks whether the winner's metric beats `spt_assert_metric(S,I)` -- the term
that exists for a router with (S,G) join state that has not set SPTbit yet.
*Check: sec. 4.6.2, `doc/rfc7761.txt:4753` for the order the two are run in
and `:4767` for the rule that keeps the (\*,G) one out of it, with the two
worked examples at `:4778`; `lost_assert(S,G,I)` is sec. 4.6.5, `:5294`, and
the Note at `:5305` says what the metric term is for.  Effort:
medium; the per-interface state is in place, it is the second copy of it on
the (\*,G) and the ordering between them that is missing.  Test: none.
`assert-lan` in `test/freebsd-interop.sh` is the topology -- R3 holds both
an (S,G) and a (\*,G) for the contended group there -- and its `rpt-bit`
and `tiebreak` sub-cases already move R3 between the two.*


Timers
------

Sec. 4.11 values against `src/pimd.h` and friends.  Rows that agree are listed
so the next reader does not re-derive them.  The spec side of the whole table is
sec. 4.11, `doc/rfc7761.txt:6895`, one table per timer name, and sec. 4.10,
`:6804`, lists the timers themselves.

| Spec name | Spec default | pimd | Verdict |
|---|---|---|---|
| Hello\_Period | 30 s | `PIM_TIMER_HELLO_INTERVAL`, settable | ok |
| Triggered\_Hello\_Delay | rand(0, 5 s) | rand(1, 30 s) at boot, immediate on trigger | T3 |
| Default\_Hello\_Holdtime | 105 s | 105 s, sent and used as the NLT fallback | ok |
| J/P\_HoldTime | from message | as received | ok |
| J/P Holdtime sent | 210 s | `PIM_JOIN_PRUNE_HOLDTIME` 210 s | ok |
| t\_periodic | 60 s | `PIM_JOIN_PRUNE_PERIOD` 60 s | ok |
| t\_suppressed | rand(1.1, 1.4) × t\_periodic | 60–89 s, RFC 2362's 1.25 × period | T2 |
| Suppression\_Enabled | from the T bit | always on | M2 |
| t\_override | rand(0, 2.5 s) | 0–4 s integer, on a 5 s tick | T1 |
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

**T1.  `t_override` is RFC 2362's constant, quantized away.**
`PIM_RANDOM_DELAY_JOIN_TIMEOUT` is 4.5 (`src/pimd.h:65`), which is RFC 2362's
`[Random-Delay-Join-Timeout]`, a different quantity from 7761's Override_Interval.
`(RANDOM() % (int)(10 * 4.5)) / 10` into a `uint16_t` yields 0 to 4 whole
seconds, and the timer only fires on the next 5-second tick, so the delay is
effectively the tick phase and the randomization does nothing.  An override Join
can therefore arrive about 5 seconds after the Prune it must cancel, against a
conformant upstream that deleted the oif after 3.  Against another pimd it is
masked by M2.
*Check: the `t_override` row of sec. 4.11, `doc/rfc7761.txt:7077`, and
`Effective_Override_Interval(I)` in sec. 4.3.3, `:1925`.  Effort: small for the
constant, medium for sub-tick scheduling.  Test: none.  It needs a shared LAN and
a peer that deletes the oif after 3 seconds rather than pimd's 5, so
`assert-lan` in `test/freebsd-interop.sh` is the natural home.*

**T2.  `t_suppressed` uses RFC 2362's range, and (\*,G) suppression is inert.**
The interval is `PIM_JOIN_PRUNE_PERIOD + 0.5 * (RANDOM() % PIM_JOIN_PRUNE_PERIOD)`,
60 to 89 seconds where the spec wants 66 to 84; the low end equals `t_periodic`
exactly, so a suppressed router can still send in the same period.  Worse, the
(\*,G) branch computes its guards and then falls through with no `SET_TIMER` at
all — three tests followed by a bare `continue` (`src/pim_proto.c:1526-1535`).
The assignment was deleted in `892acbe`, "Fix random loss of multicast, lasts
5-10 mins, by Ventus Networks", as a workaround, so every router on a LAN now
sends its own periodic Join(\*,G).  The effect is control-plane noise rather
than lost traffic, which is why it was tolerable, but restoring it needs the
original loss scenario reproduced first: the bug it papers over is most likely
in `join_or_prune()` or the `jp_timer` accounting.  Note also the address
tiebreak in those guards has no counterpart in RFC 7761.
*Check: the `t_suppressed` row of sec. 4.11, `doc/rfc7761.txt:7070`; the "See
Join(\*,G) to RPF'(\*,G)" transition that arms it is sec. 4.5.4, `:3543`, and
its (S,G) twin sec. 4.5.5, `:3815`.  Effort: small to fix, medium to fix
safely.  Test: none.  Join suppression needs two routers wanting the same group
on one segment, which `shared-lan` and `assert-lan` both have.*

**T3.  `Triggered_Hello_Delay` is not implemented in either direction.**
`src/vif.c:321` picks rand(1, Hello_Period) rather than rand(0, 5 s), and
`send_pim_hello()` overwrites `uv_hello_timer` unconditionally at its end
(`src/pim_proto.c:606`), 36 lines later in the same call path — so the
randomized startup value never survives a single tick and every router's first
Hello goes out at t=0.  The triggered Hello answering a new or rebooted neighbor
is sent immediately instead of after rand(0, 5 s), and resets the periodic
schedule, so a whole LAN answers a rebooting router in the same instant and then
converges onto its clock.
*Check: sec. 4.3.1, `doc/rfc7761.txt:1612` (startup) and `:1670` (the triggered
Hello answering a new neighbor); the value is the `Triggered_Hello_Delay` row
of sec. 4.11, `:6958`.  Effort: small; it needs a `send_pim_hello()` variant
that leaves the timer alone.  Test: none; it is startup timing, and every lab
here starts its routers together.*

**T4.  `stop_vif()` sends no goodbye Hello, on paths that could no longer send
one.**  Sec. 4.3.1 wants a zero-holdtime Hello so a DR can be re-elected at
once, and the send half is there in both places that can use it: `cleanup()`
sends one on every vif before the daemon exits (`src/main.c:590`), and
`renumber_vif()` sends one from the old address before taking the VIF down
(`src/vif.c:545`).  `stop_vif()` itself still has the two TODOs
(`src/vif.c:429-433`), but every path into it has either sent the Hello
already or cannot send one: `check_vif_state()` reaches it only once
`SIOCGIFFLAGS` reports the interface gone or `IFF_UP` clear (`src/vif.c:662`,
`:677`), and `update_reg_vif()` only for the register vif, which has no
neighbors.  That leaves `restart()` (`src/main.c:770`), where the interfaces
are still up -- and it starts them again immediately, so the Hello that follows
carries a new GenID and the neighbors re-elect on that instead.
*Check: sec. 4.3.1, `doc/rfc7761.txt:1692`; the zero-Holdtime meaning is sec.
4.9.2, `:6077`.  Effort: small, and worth only the `restart()` case.  Test:
`renumber` in `test/freebsd-lab.sh` drives the path that does send one, and
reports rather than asserts whether it arrived -- a poll cannot get ahead of an
address that has already gone.*

**T5.  `hello-interval` has no lower bound, and 0 is fatal.**
`man/pimd.conf.5:119` documents 30 to 18724 and calls anything under 30
unsupported.  `src/config.c:1451` enforces the ceiling only, so
`hello-interval 0` reaches `RANDOM() % pim_timer_hello_interval`
(`src/vif.c:321`) and kills the daemon with SIGFPE on the first vif started,
while 1 to 29 are accepted silently and drag the holdtime down with them.  Every
other range check in `config.c` warns and falls back to the default.  Not an RFC
item; listed because the audit walked into it.
*Check: no rule to check against; the nearest thing the spec says is the
`Hello_Period` row of sec. 4.11, `doc/rfc7761.txt:6956`, which gives the
30-second default and no range.  Effort: small.  Test: none.  It is a config
parse, so it wants a unit test rather than a lab.*


Interop details
---------------

**I1.  The Null-Register dummy IP header says protocol 17.**  Sec. 4.9.3 asks
for 103.  `src/pim_proto.c:965` sets `IPPROTO_UDP` with an `XXX: bogus` comment;
everything else in the dummy header matches.  An RP that inspects the inner
protocol may drop it, after which the DR re-adds the register tunnel every
60 to 90 seconds.
*Check: sec. 4.9.3, `doc/rfc7761.txt:6253` for the dummy header, the `IP
Protocol` row at `:6269`.  Effort: small.  Test: no assertion, but `arista-rp` in
`test/freebsd-interop.sh` shows the harm is not universal: EOS decapsulates
pimd's Register with its protocol 17 dummy header and register-stops it
normally.  An RP that does inspect the field is what this needs.*

**I2.  ECN and DSCP are not copied into the Register header.**  Sec. 4.4.1 asks
for both.  `ip_tos` is written once at startup (`src/pim.c:110`) and neither
`send_pim_unicast()` nor `send_pim_register()` touches it per packet, so
registered traffic crosses the DR-to-RP path as best-effort Not-ECT however the
source marked it.
*Check: sec. 4.4.1, `doc/rfc7761.txt:2291` (ECN) and `:2303` (DSCP); the RP's
side of the same copy is sec. 4.4.2, `:2443` and `:2446`.  Effort: small.  Test:
none.*


Checked, no action
------------------

- **The Border bit is already compliant.**  Sec. 4.9.3 deprecates it: set 0 on
  transmission, ignore on reception, which is what the code does.  The
  outstanding TODO at `src/pim_proto.c:615-618` describes RFC 2362 PMBR
  behaviour and has no code behind it; with (\*,\*,RP) and PMBR removed from this
  tree the right change is deleting the comment.  *Check: sec. 4.9.3,
  `doc/rfc7761.txt:6233`.*
- **Register-Stop rate limiting is not an RFC requirement.**  Sec. 4.4.2
  prescribes one Register-Stop per qualifying Register and no rate limit; the
  DR's suppression timer is the pacing mechanism.  The TODO at
  `src/pim_proto.c:1038` can go.  Its security dimension is real but belongs to
  V3.  *Check: sec. 4.4.2, `doc/rfc7761.txt:2364` for the pseudocode and `:2402`
  for its Note (\*).*
- **(\*,\*,RP) group sets are skipped, which is what RFC 7761 wants.**  The
  promise of a second pass in the comment at `src/pim_proto.c:1675` is stale —
  there is no second pass — but the resulting behaviour is correct.  The
  suppression half of the same function still has live (\*,\*,RP) handling, and
  `pack_and_send_jp_message()` can still encode such a group set, though no
  caller asks it to.  *Check: Appendix A, `doc/rfc7761.txt:7567`, which is where
  RFC 4601's (\*,\*,RP) support was removed.*
- **Sec. 4.5.6's compound Join(\*,G)+Prune(S,G,rpt) is implemented**, through
  `MRTF_RP` entries pulled into the same group set (`src/route.c:1454-1502`) and
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
  (`src/route.c:1017`, `src/pim_proto.c:2660`).  *Check: sec. 4.2,
  `doc/rfc7761.txt:1425`, where `oiflist = oiflist (-) iif` is a step of the
  forwarding rules and not part of the olist macros of sec. 4.1.5, `:1131`.*
- **`lost_assert()` is already enforced for local members.**  `calc_oifs()`
  (`src/route.c`) merges `leaves` into the outgoing interfaces and subtracts
  `asserted_oifs` immediately after, so an assert loser does not forward to
  its local members even though the leaf bit stays set in `mrt->leaves`.  The
  bit is IGMP state, not a forwarding decision; read the order in
  `calc_oifs()` before concluding otherwise.
- **`rpentry->mrtlink` is always NULL.**  The only write to any `mrtlink` is
  `grp->mrtlink` in `insert_grpmrtlink()` (`src/mrt.c:721`), so with (\*,\*,RP)
  gone nothing hangs an entry off an RP entry any more.  The blocks that read
  `rp->mrtlink` — in `delete_pim_nbr()` and in `find_route()` — are dead.  This
  is also what makes the V4 sweep over `grplist` complete: every live
  `mrtentry_t` is either a group's `grp_route` or on its `mrtlink`.
- **`send_periodic_pim_join_prune()` is dead code.**  Its only caller is inside
  `#ifdef TOBE_DELETED` (`src/vif.c:822-834`).  All Join/Prune generation happens
  in `age_routes()` and `send_pim_join()`.  Worth knowing before reading it as
  the periodic sender it is named after.
