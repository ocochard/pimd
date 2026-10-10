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
4.4 (Register), 4.5 (Join/Prune, both directions), 4.6 (Assert), 4.7 (RP
discovery), 4.8 (SSM), 4.9 (packet formats), 4.10 and 4.11 (timers), and
sec. 6 (security considerations).  Every normative section of the RFC has
now been read against the code once.  What has not is RFC 5059, which owns
the BSR mechanism 4.7 names without specifying -- the RP discovery, packet
format and authentication sections say how far into that RFC their own
entries reach and no further -- nor RFC 5796, which sec. 6.3 defers IPsec
to and which asks nothing of this daemon.

Each entry carries an effort estimate.  "Small" means a localized change,
"medium" means new bookkeeping in existing structures, "large" means state
pimd does not have today.  When one is fixed, delete the entry; when one is
confirmed to be intentional, move it to the last section with the reason.

A deviation that a test reproduces should be asserted through `xfail()`, in
`test/lab.sh` or `test/freebsd-interop.sh`, rather than left
unasserted, so that it flips to `ok` the day it is fixed.  Eleven are carried
that way and all eleven report `ok`, so every one of them is now a tripwire
against the deviation coming back rather than a live report: the assert
RPT-bit entry of 4.6.1 in `shared-lan-spt`, the SPTbit entry of 4.2.2 in
`assert-lan`, the assert winner state of 4.6.1 and 4.6.2, which `assert-lan`
asserts from both sides, and the (S,G) machine's reach past a lost (\*,G),
which the `rpt-bit` sub-case of `assert-lan` asks for, and the six of
`crafted` for M1's (S,G,rpt) machines, steps 10, 11 and 13.  A `KNOWN` line in a
run is therefore a regression, not an expected result.

Every entry below ends with a `Test:` note saying what reproduces it, and
only S1's says `none`: both fields of M4 are covered, so is the
half of A3 that pimd can be held to, by the `register-filter` scenario of
`test/lab.sh`, and so are A4's two caps, by `crafted` and
`keepalive`.  What the fixed entries are asserted by is named
where each section says it is fixed, not here.  The point of writing it down is that the gap is
visible from this list rather than only from grepping the labs.  Where an entry names a
scenario without asserting anything, it is because that scenario builds the
topology the deviation needs and stops short of the assertion; those are the
cheap ones to close, and the two that were cheapest are gone -- R1, the
Bootstrap that deleted a configured RP, and S5, the any-source report for an
SSM group -- each closed with the scenario its own note named.  Several are not
blackbox-testable at all, and say so: a five-second latency or a startup race
cannot be told from a slow lab.  The group that wanted a message pimd will
not send is gone entirely: `test/pimsend.c` builds one PIM message with any
field set to anything and sends it once, and the `crafted` scenario of
`test/lab.sh` closes and asserts the whole packet format section,
S3 and S4 of the SSM one, T2's Join suppression, T1's override Join and
T3's triggered Hello, R2's longer group range, R3's No-Forward bit, A1's
neighbor list and M1's (S,G,rpt) state.

What is left divides in two.  S1 is state pimd does not keep, a
structural change rather than a check: SSM groups that carry no RP.  A3,
A4 and the default half of M4
are the ones that stay open on purpose: the first because the kernel
decapsulates before the daemon is handed anything, the second because sec. 6.4
describes rather than prescribes -- A4 is closed for data from a DR's own
LAN and for Prune(S,G,rpt), and open for Joins and Hellos -- and the third
because a router that derives its assert preference from the routing table
beats one that cannot before either metric is read, so deriving it is a
domain-wide decision and `assert-preference rib` is how a pimd.conf makes
it.  No parser entry is left.


Input validation and trust
--------------------------

Every entry this section held is fixed: V1, an unbounded parse in
`receive_pim_register_stop()`; V2, Join/Prune and Assert accepted from any
host on the subnet; V3, a Register creating routing state before the
I\_am\_RP test; and V4, a freed neighbor left in `mrt->upstream` by an
assert.  The section stays, and keeps its numbering, because these are the
entries where a compliance gap was also a way in, and the next reader should
know they were looked for rather than wonder.

Every one of them was found by somebody reading the code.  `test/fuzz/` is
the other way to look now -- `fuzz_pim` and `fuzz_igmp` call `accept_pim()`
and `accept_igmp()` in process, tens of thousands of times a second, under
the sanitizers and with the receive buffer poisoned past the end of each
packet -- and the `Test:` notes below say where that reaches a path the labs
cannot.

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
repair.  Test: `test/fuzz/fuzz_igmp.c`, which is the one thing here that can
say what a kernel would not -- it hands `accept_igmp()` a whole IP packet, so
an upcall truncated to any length and a `WHOLEPKT` whose inner `ip_len` claims
anything at all are both inputs it can generate, and the three `upcall-*.bin`
seeds of `test/fuzz/corpus/igmp/` are where it starts.  What makes an
over-read visible rather than a read of stale bytes in a 128K buffer is that
the harness poisons the buffer past the end of each packet; without that this
deviation would have been invisible to a run of any length.  The labs give the
other half, that the guards refuse nothing a real kernel sends: `rpt`,
`keepalive`, `rp-lasthop`, `rp-offpath` and both `gif-tunnel` scenarios of
`test/lab.sh` register through this path, and `arista-rp` and
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
with the same caveat -- the kernel writes that field.  Test:
`test/fuzz/fuzz_igmp.c` again, where `im_vif` is a byte of the input and every
value of it is one the harness will eventually try; the guard is at the top of
both functions, so a run that reaches them reaches it.  Every scenario that
forwards traffic drives
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

The last of the SPTbit conditions is worth writing down, because the shape
of the mistake was not a missing feature but a question asked in the wrong
words, and because what looked like a delay was permanent.  The third
alternative of `Update_SPTbit(S,G,iif)` is `inherited_olist(S,G,rpt) ==
NULL`, and `update_sptbit()` (`src/route.c`) answered it with "is there a
(\*,G) entry at all", on the reasoning that where there is none there is
nothing to inherit.  A last hop router that loses an Assert on its own RPF
interface has one, with an empty olist -- that is what losing does -- so
nothing wants the packet on the RP tree and the alternative should fire,
while the entry test says no.  The fourth cannot cover for it: `RPF'(*,G)`
follows the Assert winner where `RPF'(S,G)` keeps the MRIB next hop, which
is the case the paragraph after the pseudocode singles out as the one
needing item (3), "because there may not be any (\*,G) state to trigger an
Assert(S,G) to happen".  With every alternative false the bit was never set,
`CouldAssert(S,G,I)` false with it, and the router asserted as an RPT
forwarder for the life of the entry: two routers on one segment then held
Assert Winner on different entries, one on its (S,G) and one on its (\*,G),
and both kept forwarding a stream no later Assert could settle.  The olist
`calc_oifs()` already keeps answers the alternative as written, since the
three terms sec. 4.1.3 subtracts are (S,G,rpt) state pimd does not have and
all three only subtract.  *Check: sec. 4.2.2 `doc/rfc7761.txt:1522`, the
paragraph that needs item (3) at `:1565`, the macro at `:1137`.  Test:
`shared-lan-spt` of `test/lab.sh` reproduces it, and only in
parallel -- `-j 4 run all` failed its assert election four runs out of four
while the scenario passed alone in every slot, the pool being what leaves a
router the Assert loser on its RPF interface often enough to reach the
state.*


State machines pimd does not have
---------------------------------

Fourteen entries this section held are fixed.  M3, the assert winner state,
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
table's now as well, and so is the preference beside it wherever the kernel
names the protocol that installed a route and a pimd.conf asks for it, M4
below.

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
told apart in `calc_oifs()`, which M1's fix did not do: it added
`calc_rpt_oifs()` for `PruneDesired(S,G,rpt)` beside it rather than change the
olist pimd forwards off.  `immediate_olist(S,G)`, the half the Note under
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

The Propagation_Delay pimd advertises is the 0.5 s default, which makes the
interval 3 seconds between two pimds.  It was `TIMER_INTERVAL`, 5 seconds, for
as long as an override Join waited for the next tick, which is the lower bound
the same section asks implementers to enforce "to allow for scheduling and
processing delays within their router"; the Join Timer schedules its own pass
now, so the default covers pimd's own delay.  The Prune-Pending Timer is a
deadline per (entry, interface) of its own, `pp_expires` beside
`prune_pending_oifs` (`src/mrt.h`), and runs out at the interval to the
millisecond; it used to be the Expiry Timer lowered to the interval and aged
five seconds at a time, armed one tick longer so that a first tick coming a
moment after the Prune could not end it short, which made it 5 to 10 seconds.
"For forwarding purposes, the Prune-Pending state functions exactly like the
Join state", a Join meanwhile clears the bit, and the PruneEcho sec. 4.5.1
owes the LAN goes on expiry, for a prune and not for a membership that simply
ran out.  The
T bit is advertised clear: it offers to disable Join suppression, which pimd
cannot do, so `Suppression_Enabled(I)` is true on every link it is on and the
explicit tracking the bit exists for stays out of reach.  Propagation_Delay
and Override_Interval are constants rather than the configuration sec. 4.3.3
says they SHOULD be; nobody has asked to move them yet.

M6 is the ninth, the secondary address list of sec. 4.3.4.  Every Hello
carries the Address List option when its interface has addresses besides
the one the VIF is built on (`vif_secaddrs()`, `src/vif.c`, at startup and
on every interface poll, a change being announced with a Hello at once as
sec. 4.3.1 asks), and every neighbor's list is kept, replaced by each Hello
and cleared by one without the option.  `find_pim_nbr_nexthop()`
(`src/route.c`) is the section's `NBR()`: an RPF next hop that is a
neighbor's secondary address maps to that neighbor, in `set_incoming()`,
`find_pim_nbr()` and the RPF check of a Bootstrap, where it used to be
"NOT A PIM ROUTER" and no Join.  An address two neighbors advertise goes to
the last one, logged at most once a Hello period.  A list pimd cannot read,
another family or not a whole number of IPv4 entries, is taken as no list
rather than as a reason to refuse the Hello.  Two limits: a VIF advertises
at most 32 secondary addresses, `MAX_SECADDRS` (`src/vif.h`), and says so
at startup when it has more; and pimd still takes a Join/Prune as its own
only when the upstream neighbor field is its primary address, which a
neighbor implementing this section always sends.  `alias` in
`test/lab.sh` asserts the encoder through tcpdump and the mapping
between two pimds, the RP joining toward the first hop router through its
secondary address; `crafted` asserts the parser on a list pimd did not
write, kept, primary address excluded, unreadable and absent.  The Linux
suite in `test/` asserts none of it.

M15, M16 and M17 are the last three, and none was ever written down as an
entry: all three turned up as `assert-recover` in `test/lab.sh`
failing one run in ten or so once enough labs ran beside it to move the
timing.  M15
was sec. 4.6.2 on a router's RPF interface.  CouldAssert is FALSE there, so
the router never wins and its own metric is not a question: it loses to any
acceptable Assert, keeps the winner, which sec. 4.1.6 makes `RPF'(*,G)`, and
replaces it only with a preferred one.  `assert_machine()` measured each
Assert against the router's own route to the RP instead, as though the
neighbor the routing table named were asserting with it, so a downstream
router nearer the RP than the routers contending above it found every Assert
inferior and went on sending its Joins to the loser -- and each one took the
loser out of its Loser state again, "Receive Join(\*,G)" in the same section.
The LAN flapped once a Join/Prune period, and `assert-recover` failed
whenever the flap fell between the winner's restart and its first Hello.  The
Loser state on the RPF interface is kept now, including where the winner is
the router the routing table names, and when it ends -- the winner's inferior
Assert or AssertCancel, the timer, the winner's GenID or its Neighbor
Liveness Timer -- the Joins go back to the routing table's neighbor after
`t_override` (`assert_rpf_restore()`).  M16 was a local member heard before
the RP was known.  `add_leaf()` builds (\*,G) state only for a group with an
RP, so the membership was recorded and never offered to PIM again until the
host reported once more, up to a query interval later, where sec. 4.5.6 has
`JoinDesired(*,G)` follow the membership as soon as `RP(G)` exists.  A router
that has just started is exactly there -- its startup query draws the report
within seconds and the RP set can take a Bootstrap period longer -- and that
was the other way `assert-recover` failed.  `add_rp_grp_entry()`
(`src/rp.c`) offers every membership to `add_leaf()` again when a range gains
its first RP, `igmp_resync_leaves()`.  M17 was the RP answering the first
Register of a source nobody had joined yet.  Sec. 4.4.2 sends that
Register-Stop only where `SwitchToSptDesired(S,G)` holds, and starts
`KeepaliveTimer(S,G)` with it, so that `JoinDesired(S,G)` turns true as soon as
a receiver joins and the RP pulls the source itself.  `receive_pim_register()`
sent the Register-Stop whatever the policy and kept no Keepalive Timer, so a
receiver joining a second after the first packet got nothing until the DR's
Register_Suppression_Time ran out, 30 to 90 seconds, which is what "no assert
settled the LAN in 90s" was.  The RP sets `MRTF_KAT` with the Register-Stop
now, where the SPT threshold is zero (`spt_switch_on_first_packet()`), and
sends none otherwise.  Step 4 of `assert-recover` asserts M15 directly: the
downstream router reads L on its RPF interface.

M18 was the one transition of the Loser state no code took: sec. 4.6.1's
"RPF_interface(S) stops being I" and sec. 4.6.2's "RPF_interface(RP(G))
stops being I", Actions A5.  None of the places that move an entry's
incoming interface -- `change_interfaces()` and the three in `age_routes()`
and `switch_shortest_path()` that set it themselves (`src/route.c`) --
touched the assert state of the interface left behind, so the Loser state
there outlived the route that made the winner RPF', for up to its Assert
Timer, and was read as a loss on what had become a downstream interface:
measured, a router with a member on the interface it had just left kept
that interface out of its outgoing list, two runs out of two.
`assert_iif_moved()` (`src/pim_proto.c`) is the
transition now, called from all four once `incoming` has moved.  Found by
mapping sec. 4.6 against the code transition by transition
(`aidd_docs/plans/assert-machines-map.md`, untracked).  *Test: step 9 of `assert-recover` moves the
downstream router's route to the RP onto a link of its own, at a metric
worse than the winner's so that sec. 4.6.2's other way out of the Loser
state, "my metric becomes better", cannot be what clears it, and with a
member of its own on a third link so that the entry outlives the move: the
router is not the DR on the LAN it leaves, and without one it ages the
entry out a pass later, correctly -- which a first version of the step,
reading the state in that window, mistook for the bug's doing.  The BSR is
the RP's own address, so the move takes the RPF check of the Bootstraps
with it; the new neighbour sends them for the length of the step.*

M19 was the (\*,G) machine taking an Assert it has no transition for, found
by the same map.  Sec. 4.6.2 moves it on `RPF_interface(RP(G))` only on an
Assert with the RPT bit set; one without the bit is about one source's
shortest path tree and is the (S,G) machine's.  `assert_machine()` gated the
bit on its RPF-interface branch for entries without `MRTF_RP` alone, and the
(\*,G) entry carries it, so where no (S,G) entry took the message first an
Assert naming any source put the (\*,G) machine into Loser state and moved
`RPF'(*,G)` -- the upstream neighbour of the whole group -- to its sender.  The
branch refuses such an Assert for the (\*,G) machine now, which loses no
transition: a metric without the RPT bit is better than any with it, so it
is never the inferior Assert that ends a Loser state either.  *Test: step 7b
of `crafted` sends both from a neighbour on R1's link to the RP, for a source
R1 holds no (S,G) for: without the bit R1 has to stay NoInfo (it read L before
the fix), and with it, the control, it has to go Loser.*

M20 was two halves of one mistake about which machine an Assert election
belongs to, found by the same map.  "Data arrives from S to G on I" is the
(S,G) machine's NoInfo event where CouldAssert(S,G,I), which wants
SPTbit(S,G), and the (\*,G) machine's where the router forwards S off the
shared tree.  `process_cache_miss()` and `process_wrong_iif()` recorded the
Winner state on whatever entry the lookup returned, so an (S,G) entry without
SPTbit -- an (S,G)RPbit entry, or one `switch_shortest_path()` made before
data came down the new tree -- won the (\*,G) machine's election, with the RPT
metric.  And `assert_machine()`, having lost a comparison to an Assert with
the RPT bit on an (S,G) entry, returned before acting whatever the state, so
such a winner kept the interface against every Assert with the bit that beat
it, where sec. 4.6.1's Winner state goes to Loser on any preferred Assert.
`assert_on_data()` (`src/route.c`) gives the event to the machine it belongs
to now, and the Winner state is excepted from that return.  *Test: none in a
lab -- no topology here puts data on an outgoing interface of an (S,G) entry
without SPTbit deterministically.  The fuzz router of `test/fuzz/` does, with
the committed `upcall-wrongvif.bin` seed: `FUZZ_DEBUG=1
test/fuzz_igmp_replay test/fuzz/corpus/igmp/upcall-wrongvif.bin` logs "Assert
Winner on fz1 for (10.0.1.9,239.1.1.1)" before the fix and "for
(*,239.1.1.1)" after it.  The second half has no reproduction at all, the
state it acted on being the first half's.*  *The second half was wrong and is
undone by M29: sec. 4.6.1's prose makes the Winner state's "Receive Preferred
Assert" "an (S,G) assert", RPT bit clear, which the table cell leaves out.*

M22 was the RP's own metric.  Sec. 4.6.3 has rpt_assert_metric(G,I) from
MRIB.pref(RP(G)) and MRIB.metric(RP(G)), and for the RP itself the route to
RP(G) is its own address: preference 0 and metric 0, the best an Assert can
carry.  `add_cand_rp()` (`src/rp.c`) looked the route to an RP up only when
the address was not one of its own, and left the `~0` it had initialised the
entry with otherwise, so an RP forwarding its shared tree onto a LAN asserted
with the infinite metric of an AssertCancel (sec. 4.6.4) and lost the election
to every other router there, whatever their distance to the RP.  It asks
`set_incoming()` in both cases now, which gives an address of its own the
register vif, as before, and the metric of a connected route.  *Test:
`crafted` step 7c in `test/lab.sh`: a neighbour on the RP's link to R1 joins
the shared tree of a group at R2 and asserts on that link with the RPT bit and
a metric of 1, which R2 has to win (it read L before the fix); the control is
an Assert at R2's own metric from a higher address, which R2 has to lose.
The fuzz router shows the wire: `upcall-wrongvif.bin` replayed with
`FUZZ_DEBUG=1` logs "Send PIM ASSERT CANCEL" before the fix and "Send PIM
ASSERT" after it.*

M23 was found by a prover rather than by a reader: `proof_decide` in
`test/cbmc/assert.c` writes the two tables of sec. 4.6.1 and 4.6.2 out as a
spec and checks `assert_decide()` (`src/pim_assert.c`) against them for
every input.  On the RPF interface the (S,G) machine's Loser state goes back
to NoInfo on "Receive Inferior Assert or Assert Cancel from Current Winner",
and an AssertCancel carries the RPT bit, sec. 4.6.4.  The upstream branch
refused every Assert with the bit on an (S,G) entry without MRTF_RP before it
looked at what it was, so the winner's cancel was dropped, and RPF'(S,G)
went on naming a router that had said it would stop forwarding until
Assert_Time ran out -- the black hole the cancel exists to prevent.  The
(\*,G) machine reached the same transition through its own path.  The
winner's cancel is tested first now, for either machine.  *Test: `crafted`
step 7d in `test/lab.sh`: r2 is given an (S,G) whose RPF interface is its
link to r1 and loses it there to a neighbour, the control, whose AssertCancel
then has to take r2 back to NoInfo (it stayed the Loser before the fix).*

M24 came out of the same proof, beside M23.  On the RPF interface
my_assert_metric is infinite, CouldAssert being FALSE there, so sec. 4.6.3's
"never considered inferior if my_assert_metric is infinite" leaves the
winner's Assert, whatever its metric, an acceptable one: both machines stay
Loser and store it, A2, and only the cancel ends the state.  `assert_decide()`
compared it against the metric the winner had won with instead, and went back
to NoInfo on any that was worse -- RPF' back to the routing table's
neighbour, the Joins with it, while the winner went on forwarding onto the
LAN.  *Test: `crafted` step 7e in `test/lab.sh`, inside 7d's setup: the
winner's Assert at a worse metric has to leave r2 the Loser (it read NoInfo
before the fix), and 7d's cancel after it still has to end the state.*

M25 is map finding 5 of the sec. 4.6 review, which the same proof confirmed.
On RPF_interface(RP(G)) an Assert with the RPT bit is the (\*,G) machine's,
sec. 4.6.1 having no transition there for one, and RPF'(S,G,rpt) is
RPF'(\*,G), sec. 4.1.6.  `assert_decide()` let an (S,G) entry on the shared
tree -- MRTF_RP, the state a Prune(S,G,rpt) makes -- take the message for its
source and follow the winner itself, which kept the (\*,G) machine out of it:
the whole group's Joins stayed on the router that had lost.  And
`age_routes()` (`src/route.c`) undid a winner either entry held, resetting
both to the routing table's neighbour -- the (S,G) entry on every check of the
unicast routes, the (\*,G) whenever one of its interface timers ran out.  The
message goes to the (\*,G) machine alone now, `assert_rpt_follow()` carries
RPF'(\*,G) over to the group's (S,G) entries on the shared tree whenever an
Assert moves it, and `age_routes()` asks `assert_rpf_prime()` for RPF' rather
than overwrite it.  *Test: `crafted` step 7f in `test/lab.sh`, read off the
new "Upstream" line of `pimctl show mrt detail`: with a (\*,G) and an (S,G)
on its shared tree at r1, an Assert with the bit for that source has to make
the (\*,G) the Loser (the (S,G) took it before the fix), both entries have to
send their Joins to the winner, still after a check of the unicast routes
(the (S,G) went back without the `route.c` half, measured), and back to r2
once the winner cancels.  The (\*,G) half of the `age_routes()` reset is not
reached: the step's Join holds its interface timers at 65535.*

M26 is the last of the four `proof_decide` reported.  Sec. 4.6.1's Loser state
stays and stores the current winner's Assert again on "Receive Acceptable
Assert with RPTbit clear from Current Winner"; one with the bit is no (S,G)
event, unless it is preferred over the winner's own last one, and sec. 4.6.2
keeps the (\*,G) machine out while the (S,G) machine is not in NoInfo.
`assert_decide()` took it either way, refreshing the Assert Timer and storing
the shared tree's metric as the winner's, so a winner that had moved to the
shared tree held an (S,G) Loser state it no longer asserted for.  Reachable
only where the (S,G) entry has no SPTbit, its own metric then carrying the bit
too.  With it `proof_decide` holds for every cell, and `test/cbmc/run.sh` runs
it with eight mutants, the four fixes undone among them.  *Test: `crafted` step
7g in `test/lab.sh`: r2's (S,G) on its link to r1, without SPTbit, loses there
without the bit, the control, and its Assert Timer has to run on past the
winner's Assert with the bit (it went back to 178 before the fix).*

M27 was M14's exception granted wider than M14 says.  The (S,G) machine
returned "cancelled", which lets the (\*,G) machine have the message as well,
for any Assert from its winner worse than our own metric, not only for the
AssertCancel M14 is about -- and sec. 4.6.2's own counter-example is that
message: the (S,G) machine goes from Loser to NoInfo on it, and the (\*,G)
one, in NoInfo, "might appear" to go to Winner, "but this is not the case".
pimd's did, on an Assert with the RPT bit.  The return code and the ordering
rule are `assert_rc()` and `assert_wc_may_run()` in `src/pim_assert.c` now,
"cancelled" is the winner's AssertCancel alone, and `proof_order` in
`test/cbmc/assert.c` proves the rule against sec. 4.6.2 and M14 for every
(S,G) machine and message, with three mutants -- the old, wider exception
among them.  *Test: `proof_order` only.  No lab here holds an (S,G) with
SPTbit, which the message needs to be inferior to, while `crafted` sends it:
`crafted` forwards data in step 13c alone, with no Assert in it.*

M28 was the last action of the (S,G) machine pimd did not take when the
transition happened.  Actions A6, NoInfo to Loser, end "If (I is
RPF_interface(S)) AND (UpstreamJPState(S,G) == Joined) set SPTbit(S,G) to
TRUE".  pimd had the same test, the last alternative of `update_sptbit()`
(`src/route.c`), "I_Am_Assert_Loser(S,G,iif)" of sec. 4.2.2, but asked it only
when data from S reached it -- an upcall or the kernel's packet count -- so an
entry that lost the election on its RPF interface before any data came stayed
an RPT forwarder, asserting with the RPT bit and sending no Prune(S,G,rpt)
toward the RP, until some did.  The glue of `assert_machine()` asks it on the
transition now.  *Test: `crafted` step 7h in `test/lab.sh`, inside 7d: r2's
(S,G), joined downstream, has to carry SPTbit once it has lost on its RPF
interface, with no data in the scenario (it did not before the fix).*

M29 was the same reading of the tables without their prose, in the Winner
state of both machines, and it was `proof_decide`'s spec that read them so.
Sec. 4.6.2 calls every event of the (\*,G) machine "a (\*,G) assert", RPT bit
set; sec. 4.6.1 calls the (S,G) Winner's preferred Assert "an (S,G) assert",
bit clear.  `assert_decide()` took the (\*,G) Winner to Loser on any preferred
Assert the (S,G) machine passed on, so an (S,G) Assert for one source took the
whole group off the interface -- which is how `shared-lan` step 13 of
`test/lab.sh` failed on Linux two runs in five, on every commit back to M20 at
least and in CI on two pushes: R3 had won the LAN, and the first hop router of
the receivers' own replies asserted for them there, R3's only (S,G) for that
source being on the shared tree and off the LAN.  It was a race, whether that
Assert came inside the step's window.  The spec in `test/cbmc/assert.c` follows
the prose now, two mutants restore the old Winner states, and the code took
the (S,G) half of the fix too, undoing M20's second half.  *Test: `crafted`
step 7i in `test/lab.sh`: r1's (\*,G), Winner on ED1's LAN, has to stay Winner
on a better Assert without the bit for a source pruned off its shared tree
there (it went Loser before the fix), and a better Assert with the bit, the
control, has to take it to Loser; and `shared-lan` step 13 on Linux, eight runs
in a row.*

M30 was a side effect of M25, found by the map of the sec. 4.5 machines that
followed the Assert work (`aidd_docs/plans/jp-machines-map.md`, U2).  Sec.
4.5.6 has a router that "is going to send a Join(*,G)" include in the same
message the Prune(S,G,rpt) of every source it holds pruned off the shared
tree, since sec. 4.5.3 reads a Join(\*,G) without it as the prune dropped.
`jp_timer_expire_sg()` (`src/route.c`) decides which (S,G) entries ride with
the Join(\*,G) by asking each about the RP's routing table neighbour, while
the Join(\*,G) goes to RPF'(\*,G).  The two are the same until an Assert moves
RPF'(\*,G), and since M25 an (S,G) on the shared tree follows it there, so the
question answered nothing: the winner got a bare Join(\*,G) every period and
put the pruned source back on the LAN until the entry's own timer sent the
Prune and its Prune-Pending time ran out.  A source-tree (S,G) whose
Prune(S,G,rpt) goes toward the RP, clause 1 of sec. 4.5.6, was left out the
same way.  It asks about RPF'(\*,G) now.  *Test: `crafted` step 7j in
`test/lab.sh`, inside 7f: r2 logs every Join/Prune r1 sends on their link,
and the first carrying r1's Join(\*,G) after the Assert -- its triggered Join
to the winner -- has to carry the Prune(S,G,rpt) too (it went alone before
the fix).*

M31 is M25's sibling, U6 of the same map.  Sec. 4.5.5's "RPF'(S,G) changes
not due to an Assert" "does not occur if an Assert is active and the upstream
interface does not change", and the unicast check of `age_routes()`
(`src/route.c`) reset a source-tree (S,G)'s upstream to the routing table's
neighbour on any change of it, and pruned the winner: the Joins went to a
router that had lost the election.  M25 had made the (\*,G) and the shared
tree's (S,G) ask `assert_rpf_prime()` there and left this branch out.  It
asks too now, after `assert_iif_moved()` has dropped the Loser state of an
interface that did change.  *Test: `crafted` step 7k in `test/lab.sh`, inside
7d: with r2 the Loser to a neighbour on its RPF interface, its route to the
source moves to a third router on the same link, and after a check of the
unicast routes its Joins have to go to the winner still (they went to the
new neighbour before the fix); after the winner's AssertCancel, the control,
they have to go to the new neighbour.*

M32 is U1 of the same map.  An (S,G) entry made by a downstream neighbour's
Prune(S,G,rpt) sits on the shared tree, MRTF_RP, and a Join(S,G) from another
neighbour makes JoinDesired(S,G) true, sec. 4.5.5: the router has to send
Join(S,G) to RPF'(S,G).  The Join(S,G) branch of `receive_pim_join_prune()`
left moving the entry to the source tree to `change_interfaces()`, which does
it only on a change of incoming interface; where the source and the RP are
reached through the same interface the entry stayed on the shared tree, and
`join_or_prune()` can answer only Prune or nothing for such an entry.  The
router went on pruning the source off the shared tree, never joined it, and
the neighbour that asked for it received nothing for as long as the other's
prune held.  The branch moves the entry itself now, upstream RPF'(S,G), and
fires its Join Timer.  What it does not get back is clause 2 of sec. 4.5.6
once that Join(S,G) times out: an entry off the shared tree no longer sends
the Prune(S,G,rpt) for an empty inherited_olist(S,G,rpt), map finding U10,
which costs the shared tree's copy of the source reaching a router that does
not forward it.  *Test: `crafted` step 7l in `test/lab.sh`: r1 reaches a
source behind r3 and the RP through r2 on the same link; one ED1 address
prunes the source off r1's shared tree, the control being r1's Prune(S,G,rpt)
on r2's log, and the other joins (S,G), after which r2's log has to show r1's
Join(S,G) for it within 70 s (none came before the fix).*

M33 is D1 of the same map.  inherited_olist(S,G), sec. 4.1.6, is built from
joins(\*,G) as it is now, so a Prune(\*,G) that takes an interface off the
(\*,G) takes it off every source of the group not held there by a Join(S,G).
A new (S,G) entry is seeded with a copy of the (\*,G)'s joined set, VOIF_COPY
in `src/mrt.h`, and `calc_oifs()` adds that copy to the (\*,G)'s live set;
`delete_leaf()` clears the copy of an IGMP membership that leaves, and nothing
cleared the copy of a Join.  A source with an (S,G) entry went on flowing out
of a pruned interface until the copied Expiry Timer ran out, up to the
holdtime, and for good under a holdtime of 0xffff.  `wc_join_gone()`
(`src/route.c`) is the counterpart now, at the three places a (\*,G) loses a
joined interface: the Prune-Pending Timer, the Expiry Timer, and a Prune(\*,G)
with no Prune-Pending time.  *Test: `crafted` step 7m in `test/lab.sh`, the
one step with a link of its own, since it needs a router with three
interfaces: ED1 joins (\*,G) on the LAN and (S,G) for a source behind r3
across the new link, the (S,G) forwarding onto the LAN being the control;
after ED1's Prune(\*,G) on the LAN it has to stop there (it went on before the
fix) and keep the link its Join(S,G) holds.*

M34 is D2 of the same map.  The periodic message of sec. 4.5.6 carries a
Join(\*,G) and the Prune(S,G,rpt) of every source its sender holds off the
shared tree in one group set, and it is what a new upstream -- after an RPF
change, or a reboot -- first hears of the group; sec. 4.5.3 takes such a Prune
from NoInfo to Prune-Pending.  `receive_pim_join_prune()` reads the Prunes of
a set before its Joins and dropped a Prune(S,G,rpt) for a group with neither
an (S,G) nor a (\*,G) yet, which the Join after it then created: the source
was forwarded until the next period.  The scan that finds the set's Join(\*,G)
ahead of both loops creates the (\*,G) now, having made the checks the Join
loop makes before creating one -- the SSM range and the RP -- and the entry
keeps MRTF_NEW for that loop's immediate Join upstream.  *Test: `crafted`
step 7n in `test/lab.sh`: one message from ED1 joining a new group and
pruning a source behind r3 off its shared tree, the (\*,G) being the control,
after which r1 has to hold the source pruned off the LAN (it held no (S,G)
before the fix).*

M35 is D3 of the same map.  Sec. 4.5.3 sets the (S,G,rpt) Expiry Timer to the
HoldTime from NoInfo, and in the Prune state and the two transient ones has it
"restarted and ... set to the maximum of its current value and the HoldTime".
`rpt_prune()` set it outright in all of them, so a neighbour's Prune with a
shorter HoldTime cut another's longer prune short, and a finite one ended a
prune held with 0xffff -- the hold of dial-on-demand links.  The (\*,G) and
(S,G) machines took the maximum already.  It does here now, a held prune
counting as the longest.  *Test: `crafted` step 7o in `test/lab.sh`: a
Prune(S,G,rpt) held 10 s lets the source back onto the LAN after them, the
control; a held one followed by the same Prune held 10 s has to keep it off
20 s later (it came back before the fix).*

M36 is U4 of the same map.  Sec. 4.5.7 counts a change of the group-to-RP
mapping among the "RPF'(\*,G) changes not due to an Assert": Join(\*,G) to the
new upstream and Prune(\*,G) to the old one, naming the new RP.
`remap_grpentry()` (`src/rp.c`) moved the (\*,G) to the new RP's upstream and
sent no Prune, so the old upstream went on forwarding the group onto the link
beside the new one until its own state for it aged out, up to the holdtime.
It calls `prune_old_upstream()` now, which an MRIB change of the same upstream
already went through and which sends nothing when the neighbour is the same
or has gone.  *Test: `crafted` step 14b in `test/lab.sh`: r1 takes a group
from r2, then a Bootstrap makes ED1 the RP for it, the (\*,G)'s upstream moving
to ED1 being the control; r2's log has to show r1's Prune(\*,G) naming ED1
(none came before the fix).*

M37 is D5 of the same map.  Figures 2 and 3 of sec. 4.5.1 and 4.5.2 give the
Expiry Timer's expiry in Prune-Pending one action, NoInfo: the PruneEcho is
the Prune-Pending Timer's, "triggered when the router stops forwarding on an
interface as a result of a prune".  `age_routes()` (`src/route.c`) sent one
on either expiry.  It came out of step 2 of the plan, the downstream machines
cut out as `jp_ds_decide()` (`src/pim_jp.c`), whose table has no PruneEcho in
that cell and which the six (\*,G) and (S,G) sites go through now.  *Test:
`crafted` step 9b in `test/lab.sh`: ED1's two addresses advertise a 20 s
Override Interval in a Hello LAN Prune Delay option (`pimsend -O`), so a
Prune-Pending Timer outlasts a 6 s Expiry Timer; a held Join pruned the same
way waits the whole interval for its PruneEcho, the control, and the 6 s
Join pruned has to send none (it sent one 5 to 10 s in before the fix).*

M38 is D6 of the same map.  Sec. 4.9.5 makes the HoldTime "the amount of
time a receiver MUST keep the Join/Prune state alive", 0xffff holding it
until canceled, and sec. 4.1.2 has the Keepalive Timer keep (S,G) state
alive "in the absence of explicit (S,G) Joins" -- a reason to keep an entry,
never one to end Join state.  pimd keeps both in the entry timer: data sets
it to PIM_DATA_TIMEOUT, 210 s, outright (`check_keepalive()` and five other
sites), under a Join that had raised it higher, and `age_routes()` deleted
the entry when it ran out, its Join and (S,G,rpt) state with it.  A source
pausing past 210 s lost a held Join(S,G) for good, the neighbour never
sending it again, and one with a HoldTime above 210 s between two
refreshes.  `sg_state_wants()` (`src/route.c`) answers how much longer the
downstream state wants the entry, and an expiry with any left re-arms the
timer -- capped at the data timeout, so that a held Join a Prune later ends
does not hold the entry for ever.  *Test: `crafted` step 13c in
`test/lab.sh`, the one step that forwards data: a second router on r1's
link to r2 holds a Join(S,G) for ED1 with 0xffff, ED1 streams to the group
for 15 s with `msend`, the join on that link being the control, and pauses;
225 s on, r1 has to hold the join still (the entry was gone before the
fix).*

M39 is U5 of the same map.  Sec. 4.5.4's "See Prune(\*,G) to RPF'(\*,G)"
takes the Join Timer down to t_override whatever RP the Prune names, as it
has to: sec. 4.5.1 has the upstream act on a Prune(\*,G) "even if the RP in
the message does not match RP(G)", and a neighbour whose group-to-RP mapping
moved first names its new RP in the Prune to its old upstream (M36).  pimd
overrode only a Prune naming its own RP, so the upstream pruned the link
under it; the override came only with the upstream's PruneEcho, which names
the upstream's RP, after the J/P_Override_Interval.  *Test: `crafted` step
7p in `test/lab.sh`: the trials of step 7, which is the control, with the
overheard Prune naming another RP; r1's Join has to reach r2 inside its
3000 ms (3.5 to 5.3 s before the fix).*

M40 is U11 of the same map.  Sec. 4.5.5, Joined state, "JoinDesired(S,G) ->
False": send Prune(S,G) and "set SPTbit(S,G) to FALSE".  pimd cleared the
bit only when the entry's outgoing list went empty (`change_interfaces()`,
`src/route.c`), and JoinDesired(S,G) can go false with the list still full
off the (\*,G): no Join(S,G) left and no Keepalive Timer, which an entry
that got its SPTbit from Actions A6 of sec. 4.6.1 and never saw data does
not have.  With the bit kept PruneDesired(S,G,rpt) stayed true, and the
source was pruned off the shared tree as well as the source tree until the
entry expired.  `change_interfaces()` asks `join_desired()` now, ahead of
its "nothing to change" return, since the list need not change for this to,
and fires the Join Timer so that the Prune(S,G) goes at once.  *Test:
`crafted` step 7q in `test/lab.sh`, at the end of 7d, where r2's (S,G)
holds the SPTbit 7h gave it and has seen no data: the downstream neighbour
joins (\*,G) too and prunes (S,G), after which the bit has to clear (it
was still set 15 s on before the fix).*

M41 is U9 of the same map.  Sec. 4.1.6 makes RPF'(S,G,rpt) the (S,G) Assert
winner on RPF_interface(RP(G)) while this router is the Loser there, and
RPF'(\*,G) otherwise.  The check of the unicast routes in `age_routes()`
(`src/route.c`) set an (S,G) on the shared tree back to RPF'(\*,G) every 20
seconds whatever held the link, and sent the winner a Prune(S,G) on the way:
sec. 4.5.7 has no message for a change of RPF'(S,G,rpt), and a Prune(S,G) is
the source tree machine's, which at the winner put any Join(S,G) on that
link into Prune-Pending.  The branch asks `assert_rpf_prime()` now, as the
source tree branch beside it does since M31, and sends nothing.  *Test:
`crafted` step 7r in `test/lab.sh`: 7f's setup with an Assert without the
RPT bit, which is the (S,G) machine's; following the winner is the control,
and after a check of the unicast routes the entry has to still follow it
with no Prune(S,G) from r1 in r2's log (it went back, and pruned, before the
fix).*

M42 is D7a of the same map.  Sec. 4.5.1 to 4.5.3: "on point-to-point links it
is RECOMMENDED that for backwards compatibility PIM Join/Prune messages with
an upstream neighbor address field of all zeros also be accepted".
`receive_pim_join_prune()` read 0.0.0.0 as a message for another router on
the link, found no neighbour by that address and dropped the whole message.
On a `VIFF_POINT_TO_POINT` interface it is this router's address now.  *Test:
`gif-tunnel` step 9 in `test/lab.sh`, the one scenario with a point-to-point
link: pimsend from r3's end of the tunnel joins ED1's source at r1 addressed
to r1, the control, and addressed to 0.0.0.0, which r1 has to take as well
(it dropped it before the fix).*

M43 is U7 of the same map.  Sec. 4.5.4 and 4.5.5 start an entry in NotJoined
and send a Prune upstream only on the transition out of Joined.  Losing an
(S,G) Assert on an interface the (\*,G) forwards onto makes an (S,G) entry
to hold the state, and its first Join Timer pass sent a Prune(S,G) to
RPF'(S,G): `jp_timer_action()` (`src/route.c`) lets the first Prune of an
entry through and holds back the repeats, MRTF_PRUNE_SENT, and a new entry
did not have the flag.  `alloc_mrtentry()` (`src/mrt.c`) sets it now, the
first Join clearing it as before.  *Test: `crafted` step 7v in
`test/lab.sh`: ED1 joins (\*,G) on the LAN and its other address wins an
(S,G) Assert there, r1 holding the entry the control; r2's log, which has
every message r1 sends on that link, has to show no Prune(S,G) in the 10 s
after (one came before the fix).*

M44 is U10 of the same map.  The second clause of sec. 4.5.6: with SPTbit
clear, an inherited_olist(S,G,rpt) that Prune(S,G,rpt) has emptied on every
(\*,G) interface adds a Prune(S,G,rpt) to the Join(\*,G), and Figure 7's
PruneDesired(S,G,rpt) says the same.  `jp_timer_expire_sg()` (`src/route.c`)
asked `join_or_prune()` about the neighbour the Join(\*,G) went to, which for
an (S,G) not on the shared tree and reached through that same neighbour
answers the source tree's question, a Join(S,G); the shared tree's was asked
only where the two upstreams differed.  An (S,G) joined on the source tree
and waiting for its first packet so took the source down the shared tree as
well, into interfaces that had all pruned it.  The pass that sends the
Join(\*,G) asks `prune_desired_rpt()` for such an entry now and adds the
Prune(S,G,rpt) to the same message, MRTF_RPT_PRUNED marking it for the
Join(S,G,rpt) that takes it back.  *Test: `crafted` step 7w in `test/lab.sh`,
on a link like 7m's: ED1 joins (S,G) for a source behind r3 across the link and
(\*,G) on the LAN, r1's entry being on the source tree with no SPTbit the
control, then prunes the source off the shared tree on the LAN; r2's log has
to show r1's Prune(S,G,rpt) within 70 s (none came before the fix).*

M1 was the (S,G,rpt) state of sec. 4.5.3, 4.5.6 and 4.5.7, which pimd kept on
the one (S,G) entry and its one `joined_oifs`/`pruned_oifs` pair.  A received
Prune(S,G,rpt) went to the (S,G) machine and took a Join(S,G) another router
on the LAN still wanted, a Join(S,G,rpt) matched no branch, and pimd never
sent one, so no router could override another's Prune(S,G,rpt) or take back
its own.  The downstream machine is `rpt_pruned_oifs` and `rpt_pp_oifs` on
the (S,G) entry now (`src/mrt.h`), with an Expiry and a Prune-Pending Timer per
interface: `rpt_prune()` and `rpt_noinfo()` in `src/pim_proto.c` are its
transitions, PruneTmp and Prune-Pending-Tmp are resolved at the end of the
group set that carried the Join(\*,G), and `calc_oifs()` (`src/route.c`)
subtracts the Prune state from what the entry inherits from `joins(*,G)` and
from nothing else.  A Prune(S,G) no longer marks the interface pruned either,
which took the source off the shared tree as well; it ends the Join state and
that is all.  The upstream machine is `prune_desired_rpt()` and
`rpt_timers_expire()` in `src/route.c`: `MRTF_RPT_PRUNED` records a
Prune(S,G,rpt) sent, so wanting the source again sends the Join(S,G,rpt) at
once, and `rpt_see_prune()` sets the Override Timer, `rpt_override`, for a
neighbor's Prune we do not want.  Steps 10 to 13 of `crafted` in
`test/lab.sh` assert all of it with pimsend playing the other routers,
which is the only way to see it: between two pimds the override Join hides
what the upstream router did with the Prune.  `rpt-override` in
`test/freebsd-interop.sh` asks the other half of the wire: that an Arista
honours the Join(S,G,rpt) pimd sends to override a Prune(S,G,rpt).  Two things are left out on
purpose.  "See Prune(S,G) to RPF'(S,G,rpt)", the event sec. 4.5.7 keeps for
routers written to RFC 2362, overrides only where an (S,G) entry exists
already rather than making one for every Prune(S,G) on the link; and "RPF'(S,G,rpt)
-> RPF'(\*,G)" has nothing to fire it, RPF'(S,G,rpt) being RPF'(\*,G) here.


M7 is the fourteenth, and it is the one entry here that was measured before it
was believed.  Sec. 4.2 restarts `KeepaliveTimer(S,G)` from arriving data, and
every write to pimd's timer of that name -- `entry_timer` -- was a
control-plane event or a kernel upcall.  Three of those cover most of the
table between them, and the cases they cover are disjoint, which is why the
`rpt` topology with `spt-threshold infinity` in all three `pimd.conf`s ran ten
minutes of continuous traffic with no entry deleted on any router: a
downstream neighbour's periodic Join refreshes an entry with an oif it asked
for, the Register probe loop refreshes the DR's and the RP's, and an entry
with an empty oif list has no MFC, so every packet of it is a cache miss that
`process_cache_miss()` refreshes it from -- which is the path the `keepalive`
scenario pins, at one upcall per packet for as long as the source sends.  What
none of them covers is a last hop router's (S,G) whose only oif is a local
member inherited from the (\*,G): nothing is joined downstream of it, nothing
is registered, and it forwards in the kernel, so the only thing that ever
restarted its timer was `switch_shortest_path()` being called again on the
spt-threshold poll.  With an `interval` longer than `Keepalive_Period` the
entry aged out under a source that had never stopped sending, `age_routes()`
deleting it through its `PIMD_VIFM_LASTHOP_ROUTER` branch because those leaves
are inherited -- no traffic lost, the (\*,G) going on forwarding and the entry
coming back at the next poll, but the switch to the shortest path tree
oscillating with the period of the poll.

"On receipt of data" is answered without the packet, the way `check_sptbit()`
already answered Update_SPTbit(S,G,iif): pimd forwards in the kernel, the
kernel counts what it forwards and matches on the incoming interface of the
entry holding the MFC, so a count that moved between two `age_routes()` passes
on an entry whose iif is RPF_interface(S) is data from S received on
RPF_interface(S).  One `k_get_sg_cnt()` per (S,G) per pass now answers both,
in `check_data_from_source()` (`src/route.c`), and the order is sec. 4.2's own:
`check_keepalive()` first, since `JoinDesired(S,G)` reads the Keepalive Timer
and Update_SPTbit(S,G,iif) reads `JoinDesired(S,G)`.  Both of the section's
rules are there -- a directly connected source, and `UpstreamJPState(S,G) ==
Joined` with a non-empty `inherited_olist(S,G)`, which here are `join_desired()`
and `calc_oifs()` -- and `MRTF_KAT` is set with the timer for the reason
sec. 4.2.1 sets it in CheckSwitchToSpt(S,G).  Step 9 of `rpt` in `test/lab.sh`
is the assertion: R3, where none of the three control-plane refreshes reaches,
holds its entry timer at 205 for a minute of traffic where it used to sawtooth
from 210 down to 155 between two polls.

**M4.  The assert metric preference is a configured constant unless a
pimd.conf asks for the routing protocol's.**  Sec. 4.6.3 and sec. 4.9.6 both
say the metric preference and the
metric are the unicast routing protocol's.  The metric is, now: `struct rpfctl`
(`src/vif.h`) carries MRIB.metric back from every RPF lookup -- the route's
priority out of the netlink reply (`src/netlink.c`, which on Linux has to ask
for the FIB entry with `RTM_F_FIB_MATCH` to get one, the resolved route never
carrying it), `rmx_metric` out of the routing socket's (`src/routesock.c`) --
and `set_incoming()` (`src/route.c`)
gives it to the source, leaving `metric` in `pimd.conf` as the fallback for a
kernel that answers neither.  Two routers on a LAN whose routing tables disagree
about the cost of reaching the source, or the RP, now elect on that rather than
on their addresses, and an election follows a route change while it runs:
sec. 4.6.1 leaves the Loser state when "my metric becomes better than the assert
winner's metric", which `age_asserts()` (`src/pim_proto.c`) evaluates once per
pass because the number can now move without pimd doing anything.

The preference is the configured one, `uv_local_pref`, 101 unless `distance`
says otherwise -- unless `assert-preference rib` in pimd.conf asks for the
routing protocol's, which is the opt-in this entry used to ask for and which
`parse_assert_preference()` (`src/config.c`) now is.  What the kernel keeps is
not a distance but which protocol installed the route: netlink carries that in
`rtm_protocol`, on both systems -- FreeBSD fills the field from the nexthop's
origin, `nl_get_rtm_protocol()` in `sys/netlink/route/rt.c`, in the same
RTPROT\_\* namespace Linux uses -- and `rtprot_pref()` (`src/netlink.c`) turns
it into the distance the industry gives that protocol: 0 connected, 1 static,
20 BGP, 90 EIGRP, 110 OSPF, 115 IS-IS, 120 RIP, which is what an Arista or a
Cisco on the same LAN advertises for the same route.  On Linux it costs no
syscall: the metric already needs the second lookup with `RTM_F_FIB_MATCH`,
since the resolved route carries no priority, and that reply has
`rtm_protocol` in the same header.  A protocol nobody has a number for, and
the ones that only say "some daemon put this here" -- RTPROT\_ZEBRA,
RTPROT\_BIRD -- are answered with `RPF_PREF_UNKNOWN` and keep the configured
distance.

The PF\_ROUTE socket `routesock.c` reads does not carry the origin at all --
`rtsock.c` fills `rtm_rmx`, which is where `rmx_metric` comes from, and never
the origin -- and that is the default build on BSD, so there `rib` reads
nothing and `distance` stands.

Off by default, and that is the rest of this entry rather than an omission.
Sec. 4.6.3 compares the preference before it ever looks at the metric, so a
pimd deriving one is unanswerable by a pimd that cannot: 110 for an OSPF route
against 101 for the same route, and on FreeBSD the difference between the two
is a `configure` flag rather than a different operating system.  Two routers
on one LAN, same routing table, different build, and the election would go to
whichever was built which way.  A domain where every router derives it, or
where none does, is a decision for whoever runs it, and the keyword is how it
is said.

One thing the metric inherits from the same asymmetry, smaller because it is
compared second: an ordinary route has priority 0 on Linux and metric 1 on
FreeBSD, so between two routers that agree on everything else the Linux one
wins.  Both numbers are what their own kernel calls the cost of that route.
*Check: sec. 4.6.3, `doc/rfc7761.txt:5215` for `spt_assert_metric(S,I)`, and
sec. 4.9.6, `:6766`, for the two wire fields.
Test: steps 12 and 13 of `shared-lan` in `test/lab.sh`, one field each, both
in both directions.  Step 12 is the metric: the two contenders reach the RP at
a metric `route change` sets, and the LAN changes hands when either one is
bettered, which with a constant metric it never did.  It runs against both
lookups -- `routesock.c` by default, `netlink.c` with `NETLINK=yes` on FreeBSD
and always on Linux, where it is what showed the Linux netlink answer carried
no metric at all.  Step 13 is the preference, with both routers running
`assert-preference rib` and the route to the RP labelled with the protocol
that is to look as if it installed it, the metrics left equal: the LAN follows
the administrative distance, against the address, and follows it back when the
labels swap.  That one needs a kernel whose routes carry a protocol and a
netlink build to read it, so it skips itself elsewhere and says which.
The other witness is the `rib` sub-case of `assert-lan` in
`test/freebsd-interop.sh`, which is the only place a *derived* pimd preference
meets a foreign implementation's: R3 reaches the source over a static route and
derives 1 against the Arista's 100, while `default-route-distance` in its own
pimd.conf says 150 -- the number the `arista-wins` sub-case beside it shows
pimd losing with, which is this one's control.  It needs a netlink build and
skips itself on a routing socket one, saying so.*

**M21.  AssertTrackingDesired is never evaluated, by choice.**  Both Loser
states of sec. 4.6.1 and sec. 4.6.2 go to NoInfo when
`AssertTrackingDesired(S,G,I)` or `AssertTrackingDesired(*,G,I)` turns FALSE
(`doc/rfc7761.txt:4431`, `:4901`), and pimd computes neither: its Loser state
ends on the Assert Timer, the winner's AssertCancel, inferior Assert, GenID
or Neighbor Liveness Timer, "my metric becomes better", a Join on the
interface, or the interface leaving the RPF interface (M18) -- every other
exit of the two tables -- but not on the router losing interest in the
interface.  Weighed rather than fixed, after the sec. 4.6 map that turned up
M18 to M20.  Downstream, a router with no interest in an interface would not
forward onto it in either state, so the two differ only when interest
returns: RFC 7761's router is in NoInfo, forwards, duplicates the winner's
traffic and loses the election again, while pimd's is still the Loser --
the winner's Assert every 177 seconds keeps it so -- and forwards nothing,
correctly while the winner still serves the link; a winner that stops does
so with an AssertCancel, which pimd acts on, and one that dies takes its
state with its Neighbor Liveness Timer.  Upstream, a Loser on the RPF
interface with no Join desired sends no Join either way, and when one is
desired again pimd sends it to the winner at once where RFC 7761's router
sends it to the routing table's neighbor and follows the next Assert.  No
forwarding difference could be constructed from either case.  Evaluating it
would approximate the four terms of the (S,G) macro and three of the (\*,G)
one from pimd's state, and a term wrong on the RPF interface reopens M15,
the Join/Prune-period flap that Loser state was fixed to stop.  *Test: none
-- the visible difference is the state alone, after a Join holdtime, 210
seconds in the labs here.*


RP discovery
------------

Sec. 4.7 leaves the choice of mechanism open and asks only that every router
in the domain arrive at the same group-to-RP mapping.  What it does pin down
is the algorithm of sec. 4.7.1, the hash of sec. 4.7.2 and that static
configuration MUST be supported; all three are in place, and the last section
says what was checked and why it needs no work.  What is left here is about
what happens to a mapping after it has been learned, and none of it is open:
R1, a Bootstrap deleting a configured RP, R2, a longer group range learned
after its groups had state and leaving them on the RP they had, and R3, the
No-Forward bit, are all fixed, and `static-rp` and `crafted` in
`test/lab.sh` assert them.  RFC 5059 owns the BSR mechanism and is in
the tree as `doc/rfc5059.txt`; it is cited where an entry needs it but has
not otherwise been read against
the code, so this section is not a statement about pimd's BSR conformance as
a whole.

Administratively scoped zones, the "notable exception" of sec. 4.7, are not
implemented.  pimd has one RP set and one BSR election, and the `scoped`
keyword of `pimd.conf` is an mrouted-style per-interface data plane filter
(`scoped_addr()`, `src/route.c:144`), not a scope zone: it drops packets, it
does not give a range of groups an RP set of its own.  A domain broken into
scope regions therefore cannot use pimd as the BSR for them, and nobody has
asked it to.
*Check: sec. 4.7, `doc/rfc7761.txt:5461`; what it would take is RFC 5059
sec. 3, which carries the scope zone through every BSR state machine it has.*

Source-specific multicast
-------------------------

Sec. 4.8.1 is six rules that override normal PIM-SM for a group in the SSM
range, and the last three of them exist for one reason, which the section
states: an SSM-unaware router may still send (\*,G) and (S,G,rpt)
Join/Prunes, or Registers, for an SSM group, and a conformant router has to
refuse to act on them.  pimd keeps all of them now.  The two rules about
what arrives were S3, a Register for an SSM group dropped without the
Register-Stop that is the only thing which quiets an SSM-unaware DR down,
and S4, a (\*,G) or (S,G,rpt) Join/Prune for one acted on; both are fixed,
and `crafted` in `test/lab.sh` asserts them with messages
`test/pimsend.c` builds, neither pimd nor the EOS of
`test/freebsd-interop.sh` being willing to send one.  The IGMP side of the
same problem, S5, is fixed too and belonged to RFC 4604 rather than to this
spec.

Rule 3 is kept on both sides now.  `send_pim_register()` never built a
Register for an SSM group, and S2 was the state that led there: the DR put
the register vif in the oifs of every directly connected SSM source, because
the RP it asked about was the invented one of S1 and never itself, and
nothing took it back out -- the Register-Stop that prunes it for an ASM
source cannot arrive for a group nobody is the RP of.  The whole SSM data
rate of those sources crossed into user space to be dropped, on the one
router guaranteed to see all of it.  `ssm` asserts the oif is absent.

What is left is S1, one entry: that an SSM group carries RP state at all.
Its dangerous half is closed -- see the entry -- and its remaining half is
worth reading before anyone estimates it.

**S1.  Every SSM group is given an RP that does not exist.**  An SSM group
has no RP and the code wants one anyway, so pimd manufactures one, twice
over and in two different places.  `config_vifs_from_file()` ends by
synthesizing a static `rp-address 169.254.0.1` for each SSM range in effect,
the default 232.0.0.0/8 included and even when there is no `pimd.conf` at
all (`src/config.c:2104-2113`); and `find_route()` has a second copy of the
same idea for a group that still matches no RP, at a /32 prefix of its own
(`src/mrt.c:209-219`, with the TODO that says the real fix is SSM-specific
state).  The first is why the second is unreachable: a static entry answers
`rp_match()` for every group in every range, so the branch in `find_route()`
is dead code in any configuration a `pimd.conf` can express.

That matters because the two are not equivalent.  The synthesized static RP
carries the static holdtime, 0xffff, which `age_misc()` leaves alone
(`src/rp.c:1046`, which ages an entry only below 60000).  The one in
`find_route()` is added with a holdtime of 90 seconds that nothing ever
refreshes -- it is added only `if (rp_match(group) == NULL)`, and while it
exists that test is false, so the path that would update an existing entry's
holdtime is never reached.  Were it ever reached, 90 seconds later
`delete_rp_grp_entry()` would remap the groups on it, `rp_grp_match()` would
answer NULL, and `remap_grpentry()` would do the only thing it can with a
group it cannot map: `delete_grpentry()` (`src/rp.c:745`), freeing every
(S,G) of the group and every kernel cache entry with it (`src/mrt.c:378`).
R1 was the way in, and the only one: a Bootstrap carrying the same group
prefix as the synthesized static RP deleted it through the fragment tag
collector, and from the next packet on the group ran on a 90-second RP that
would take the group down with it when it expired.  That is closed.  The
synthesized entry goes in through `parse_rp_address()` like any other
`rp-address` (`src/config.c:2112`), so `add_static_rp()` marks it and the
collector leaves it alone, and `crafted` in `test/lab.sh` asserts
exactly that: a well-formed Bootstrap for 232.0.0.0/8 from a real neighbor,
and the invented RP still there afterwards.  The second copy in
`find_route()` stays unreachable, which is what keeps its 90-second
holdtime from mattering.

So what is wrong here is not a live teardown, it is that an SSM group
carries RP state at all: a fictional address in `pimctl show rp`, a
group-to-RP mapping that decides `i_am_rp()` for S2, and a second
implementation of the same fiction behind it with a timer the first one does
not have.
*Check: sec. 4.8.1, `doc/rfc7761.txt:5685`, is the rule pimd is on the far
side of -- it MAY optimize the (\*,G) state out for SSM, and pimd instead
gives an SSM group more RP state than an ASM group has.  Effort: larger than
it looks, and larger than this entry used to say.  The fix is the TODO's --
keep SSM groups out of the RP machinery -- and what stands in the way is that
`find_route()` returns NULL for a group `rp_grp_match()` cannot answer
(`src/mrt.c:221-228`), so deleting the invented RP stops SSM working
altogether rather than cleaning it up.  Giving an SSM group no RP means every
reader of `grp->active_rp_grp` and `grp->rpaddr` needs an answer for "there
is none": 35 and 27 uses respectively, across `mrt.c`, `rp.c`, `route.c`,
`pim_proto.c`, `ipc.c` and `debug.c`, plus eleven `rp_match()` call sites.
That is the SSM-specific state the TODO names, and it is a structural change
to `grpentry_t` rather than a deletion.  What is left to gain is also
smaller than it was: the teardown is closed, S2 is fixed, and what remains is
a fictional address in `pimctl show rp` and a second implementation behind it
that nothing reaches.  Test: the half that is closed is asserted by
`crafted`; the rest has nothing to assert until the state exists.*

Timers
------

Sec. 4.11 values against `src/pimd.h` and friends.  Rows that agree are listed
so the next reader does not re-derive them.  The spec side of the whole table is
sec. 4.11, `doc/rfc7761.txt:6895`, one table per timer name, and sec. 4.10,
`:6804`, lists the timers themselves.

| Spec name | Spec default | pimd | Verdict |
|---|---|---|---|
| Hello\_Period | 30 s | `PIM_TIMER_HELLO_INTERVAL`, settable | ok |
| Triggered\_Hello\_Delay | rand(0, 5 s) | rand(0, 5 s) on trigger; at boot, whole seconds on a 5 s tick | ok |
| Default\_Hello\_Holdtime | 105 s | 105 s, sent and used as the NLT fallback | ok |
| J/P\_HoldTime | from message | as received | ok |
| J/P Holdtime sent | 210 s | `PIM_JOIN_PRUNE_HOLDTIME` 210 s | ok |
| t\_periodic | 60 s | `PIM_JOIN_PRUNE_PERIOD` 60 s | ok |
| t\_suppressed | rand(1.1, 1.4) × t\_periodic | 66–84 s | ok |
| Suppression\_Enabled | from the T bit | always on, T advertised clear | ok in effect |
| t\_override | rand(0, Eff. Override) | rand(0, Eff. Override), in ms | ok |
| Propagation\_Delay | 0.5 s | 500 ms, advertised and negotiated | ok |
| Override\_Interval | 2.5 s | 2500 ms, advertised and negotiated | ok |
| J/P\_Override\_Interval (PPT) | 3 s | the negotiated sum, 3 s between pimds | ok |
| Assert\_Time | 180 s | `PIM_ASSERT_TIMEOUT` 180 s | ok |
| Assert\_Override\_Interval | 3 s | 3 s, the winner rearmed at 177 s | ok |
| Register\_Suppression\_Time | 60 s | 60 s | ok |
| Register\_Probe\_Time | 5 s | 5 s | ok |
| RST(S,G) | 25–85 s | 30–90 s, the probe-time term omitted | minor |
| Keepalive\_Period | 210 s | `PIM_DATA_TIMEOUT` 210 s, set from the data | ok |
| RP\_Keepalive\_Period | 185 s | 210 s, i.e. max(210, 185) | ok in effect |

`TIMER_INTERVAL` is 5 seconds and `SET_TIMER`/`IF_TIMEOUT` count whole seconds,
so no sub-5-second spec value is representable on those timers.  The Join,
Prune-Pending and Assert Timers and the triggered Hello are the exceptions,
below.

`t_suppressed` is in force again, where it used to be computed and never set.
T2 was the (\*,G) branch of the Join suppression in `receive_pim_join_prune()`,
which had its timer assignment deleted in `892acbe` after a report of groups
lost for minutes at a time; the (S,G) branch kept its assignment and both
carried guards of their own, a comparison of the Join Timer against the
overheard HoldTime and an address tiebreak, neither of which is in the spec.
Both branches are sec. 4.5.4 and 4.5.5 now, `jp_suppress()`: the timer is
raised to `t_joinsuppress`, the smaller of `t_suppressed` and the HoldTime of
the Join overheard, and never lowered.  The HoldTime bound is the one that
matters for what `892acbe` saw: an upstream keeps the interface only as long
as the Join it heard asked, so a suppression that outlived it let the state
expire there, and the bound is what rules that out.  The report named no
topology, so the loss itself was not reproduced.  `crafted` in
`test/lab.sh` asserts both halves, with a second router on R1's
upstream link played by `test/pimsend.c`: R1 sends no Join(\*,G) of its own
while that router sends one every 20 seconds, and sends one again within a
suppression period once those Joins carry a 10-second HoldTime.

The callout queue of `src/timer.c` counts milliseconds on the monotonic clock,
and four timers moved onto it.  The Join Timer of sec. 4.5.4 and 4.5.5 is a
deadline, `jp_expires` in `src/mrt.h`, rather than a count `age_routes()` took
five seconds off: the tick still sends what has come due, the periodic Joins
among them, and a timer set to run out before the next tick schedules a pass
of its own, `jp_timer_run()`.  That was M8, every triggered Join and Prune
built on the next tick, up to five seconds after the transition the sections
send it on, the SPT switchover included; and T1, `t_override` drawn in whole
seconds and then made the tick phase, so that an override Join could reach an
upstream after the 3 seconds it waits.  A Prune goes out once on the transition
to NotJoined, where it used to be repeated every period, though the timer is
left running so that a transition back that nothing fires the timer for is
still found within a period; an (S,G)RPbit entry keeps repeating its Prune,
which is the (S,G,rpt) one sec. 4.5.8 sends with every Join(\*,G).  T3 was
the Hello answering a new or rebooted neighbor, sent at once rather than after
rand(0, `Triggered_Hello_Delay`), because the Bootstrap RFC 5059 sec. 3.5 has
the DR unicast to that neighbor followed it, and a router drops a Bootstrap
from one it has had no Hello from.  `trigger_hello()` (`src/pim_proto.c`)
schedules the Hello per interface, the Bootstraps it owes wait on the
neighbor for it, and a Join/Prune or Assert sent on the interface meanwhile
sends the Hello first, as sec. 4.3.1 requires.  `crafted` in
`test/lab.sh` times both over several trials, the override from the
Prune in R1's log to the Join in R2's, each under 3 seconds, and the Hello
from the new neighbor to R1's answer, each within 5 seconds and not all of
them prompt.  The Hello at startup is still whole seconds on a tick.

The Prune-Pending Timer, above, and the Assert Timer of sec. 4.6 followed,
onto the same pass, `route_timers_run()`.  The Assert Timer is a deadline in
`struct assert_state`, and the winner rearms at `Assert_Time -
Assert_Override_Interval`, 177 seconds.  On the tick it had been rounded down
to 175, because 177 and 180 ran out on the same tick and the resend would have
raced the refresh it is for, and a loser's 180 could end anywhere from 175
seconds on -- short of a winner that resends at 177 as the spec has it.
`crafted` times the Prune-Pending Timer from a Prune on R1's LAN to the
PruneEcho, 3000 ms to within the log's rounding, and `assert-lan` in
`test/freebsd-interop.sh` the gap before R3's resend, 177000 ms within half a
second.


Packet formats
--------------

Every entry this section held is fixed: F1, the PIM version and the
destination address, neither of which was checked; F2, the address family
and encoding type of an encoded address, parsed into a structure member
nobody read, so a record declaring another family was read at the IPv4
offsets its fields are not at; F3, a mask length wider than an address, a
negative shift and a group range nobody advertised over the domain's RP
set; F4, the B and Z bits, a Bidirectional-PIM or admin-scoped range
installed as an ordinary PIM-SM one; F5, a Holdtime of 0xffff aged like a
number rather than held; and F6, the dummy header of a Null-Register whose
checksum was never verified.  The section stays, and keeps its numbering,
for the reason the input validation one does: these are where a parser
reads the right bytes as the wrong thing, and the next reader should know
they were looked for.

One note is worth keeping.  None of them could be reproduced by a lab of
pimds, because the message that reproduces them is one pimd will not build
-- two pimds share a reading of the wire, so a field pimd encodes wrongly
it decodes wrongly to match.  `test/pimsend.c` is what got past that, the
way `test/igmpv3.c` did for IGMP: one crafted PIM message, every field that
can be got wrong exposed as an option, sent once.  The `crafted` scenario
of `test/lab.sh` guards all six, with the positive control each
needs beside it -- a parser that refuses everything passes every "was it
refused?" test ever written.  S3 and S4 of the SSM section are the same
wall, and now the same way through.

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


Authentication and denial of service
------------------------------------

Sec. 6 is short and almost all of it is description: sec. 6.1 says what a
forged message of each kind buys an attacker, sec. 6.3 points at RFC 5796 for
IPsec, and sec. 6.4 names two denial-of-service attacks without asking for
anything.  The normative content is sec. 6.2, five sentences, and they are
what this section measures.  Two of them are kept and are described in the
last section of this file; a third is kept as of the `register-accept-from`
setting, and A3 below is what that setting cannot reach; a fourth, "a PIM
router SHOULD NOT accept protocol messages from a router from which it has
not yet received a valid Hello message", is kept everywhere now that the
unicast branch of `receive_pim_bootstrap()` asks the neighbor list the way
the Join/Prune and Assert parsers already did; and the fifth, the option to
limit the set of neighbors a router accepts Join/Prune, Assert and Hello
messages from, is kept as of `accept-nbr-from` in `pimd.conf`.  That is all
five, and what is left here is A3, which is the limit of the third rather
than a gap in it, and A4, which is what
sec. 6.4 describes and pimd bounds only in part.  The first section of this file is the
neighbouring one: it holds the entries where a parser could be walked off the
end, V1 through V6, and this one holds the entries where a well-formed
message from the wrong sender is acted on, or an unbounded number of them
is.

Two things sec. 6 asks for that are not pimd's to do.  The preamble
RECOMMENDS securing the sources of change to the MRIB, which is the unicast
routing daemon's configuration and not this daemon's; and sec. 6.3's IPsec is
a security association the operator installs in the kernel for 224.0.0.13 and
for the RP's address, with no code in pimd either way.  Nothing here prevents
it, and nothing here has been tested with it -- neither lab configures an SA,
so "pimd works under IPsec" is an untested claim rather than a false one.

**A3.  The Register filter cannot reach the packet it is about.**
Sec. 6.2's mechanism "to allow an RP to restrict the range of source
addresses from which it accepts Register-encapsulated packets" exists now:
`register-accept-from` in `pimd.conf`, one or more prefixes, matched against
the sender of the Register in `receive_pim_register()`, and accepting
everything while unconfigured as the same section's last sentence requires.
What it refuses is everything the daemon would have done -- the (S,G) the
Register would have created, the Keepalive Timer it would have refreshed,
and the Register-Stop that would have gone back, which is withheld on
purpose because answering tells a forger it found the RP.

What it does not refuse is the packet.  Decapsulating a Register is the
kernel's work, which the last section of this file already records as the
literal reading of sec. 4.4.2, and the kernel does it first: FreeBSD's
`pim_input()` copies the header for the daemon and then hands the inner
packet to `if_simloop()` on the register vif
(`/usr/src/sys/netinet/ip_mroute.c`), and Linux's `ipmr` is built to the
same model.  Neither asks whether the outer destination is an RP address,
let alone who sent it.  So for a group whose shared tree is up, sec. 6.1.2's
first attack still lands, and every userspace filter pimd could grow lands
after it.

"Whose shared tree is up" is a weaker condition than it sounds, and the
scenario named below is what showed it.  A group nobody has joined is not
safe: `send_pim_register()` (`src/pim_proto.c:1250-1254`) fires the Join/Prune
timer of the group entry as the DR registers, so the DR itself joins the
tree it is registering to, and by the time the second Register arrives the
RP has a (\*,G) for the inner packets to land on.  Measured on the lab, an
RP refusing every Register from the only DR sending them still held both a
(\*,G) and an (S,G) for the group, the second built by
`process_cache_miss()` (`src/route.c`) out of the decapsulated packets on
the register vif.  What the setting keeps off the RP is the entry the
*Register* would have made and the Register-Stop; the entry the traffic
makes arrives anyway.

That leaves the honest answer being a packet filter for IP protocol 103 in
front of the RP, which `pimd.conf.5` now says.  It is worth writing down
rather than closing, because the entry that reads as closed is the one
somebody will trust: the setting is real and worth having, and it is not
the control an operator will assume it is from its name.
*Check: sec. 6.2, `doc/rfc7761.txt:7380`, for the mechanism, which is now
provided; the attack that outlives it is sec. 6.1.2, `:7352`, and the note
that makes the decapsulation the kernel's is sec. 4.4.2, `:2420`.  Effort:
out of reach from here -- it wants a kernel that filters before it
decapsulates, or a `MRT_*` interface that hands the Register to the daemon
first.  Test: `register-filter` in `test/lab.sh`, which covers the
half that is fixed and counts the half that is not.  R2 is the RP and is
given a `register-accept-from` that does not cover the address R1 registers
from -- the DR's address on the sender's LAN, sec. 4.4.2's `outer.src`, and
not the one the RP has in its neighbour table -- so every Register is
refused; then the prefix is replaced with one that does cover it and the
same stream is sent again.  The two halves are compared on the
Register-Stop, and on whether the DR still has the register vif in the oif
list of its (S,G).  Not on the RP's table: this entry used to propose "a `pimctl show mrt` on the RP with no
(S,G) in it" and that assertion cannot be had, for the reason given above.
The scenario asserts the state is there instead, so that a kernel which
ever filtered before decapsulating fails it and this entry gets rewritten,
and reads `netstat -sp pim` in the RP's vnet for the count of Registers its
kernel opened while pimd refused them.*

**A4.  Only part of the state a stranger can make pimd hold is bounded.**
Sec. 6.4 names two attacks, packets to many group addresses and a flood of
forged Joins, and says authentication prevents some but not all of them.
There is no limit on group entries, source entries, routing entries, kernel
cache entries or neighbors as such.  What pimd has instead is a cap on each
path by which someone else creates them, and two of those exist:
`IGMP_MAX_SOURCES`, 256 sources per group, which the IGMPv3 parser enforces
(`src/igmp_proto.c`), and the two below.

Three ways in, in order of how close the attacker has to be:

- A packet to a group nothing knows about is a cache miss, and on the DR for
  its source that creates a source entry, a group entry, a routing entry and a
  kernel cache entry (`process_cache_miss()`, `src/route.c`).  This is
  sec. 6.4's first bullet, and the sender needs only to be on a subnet this
  router is the DR for.  It is bounded: `local_sg_entry()` counts the entries
  it makes and past `local-sg-limit` in `pimd.conf`, default 4096, makes no
  more, while an entry that already exists is still found and refreshed.  A
  source refused that way is not registered, so it is not forwarded beyond
  its LAN, and each of its packets stays a cache miss -- one upcall per
  packet, the negative cache entry pimd does not install (the TODO in
  `process_cache_miss()`).  The limit is global rather than per source,
  because on its own subnet the sender picks the source address too.
- A Join from a neighbor creates whatever it names, up to 255 group sets in
  one message and as many sources as the message will hold, and each source
  that is new costs an RPF lookup through netlink or the routing socket
  (`set_incoming()`, `src/route.c`) as well as the allocations.  That is
  sec. 6.4's second bullet.  Since V2 the sender has to have sent a Hello
  first, which on a LAN is not an obstacle.  One kind of message in this
  bullet is bounded: a Prune(S,G,rpt) for a source pimd holds no (S,G) for,
  received or overheard upstream, makes one that lasts as long as the
  sender's HoldTime, and `rpt_prune_entry()` (`src/pim_proto.c`) stops
  making them past `rpt-prune-limit`, default 1024.  A Join(S,G) or Join(\*,G)
  is not.
- A Hello from an address never seen before allocates a neighbor entry that
  lives for the holdtime, and makes pimd answer with a Hello to the whole LAN,
  a DR election, and -- if it is the DR -- a unicast copy of the entire RP set
  (`src/pim_proto.c`).  One small forged packet in, two larger ones out, and
  an entry held either way.  Unbounded; `accept-nbr-from` narrows who can,
  where an operator knows the routers on a link.

Both limits count the entries rather than the senders: an entry records the
count it was made under (`limit_count` in `mrtentry_t`, `src/mrt.h`) and
`FREE_MRTENTRY()` gives it back whichever path frees it, a reload included.
None of this leaks: every entry has a timer, so the growth is bounded by rate
rather than unbounded in time.  What makes the rest worth an entry anyway is
the default build's answer when the allocation finally fails, which is
`logit(LOG_ERR, ...)` and an `exit(-1)` from `logit()` itself
(`src/debug.c:641-643`, absent `--disable-exit-on-error`): memory pressure an
attacker can create does not degrade this daemon, it stops it.
*Check: sec. 6.4, `doc/rfc7761.txt:7410`.  Effort: medium for each path
left, and a design question before it is work -- a cap that refuses new
state is a black hole for whoever was legitimately using it, which is why
sec. 6.4 describes rather than prescribes, and a Join refused is a receiver
cut off rather than a source not registered.  Test: the two caps are
asserted, `rpt-prune-limit` by step 13b of `crafted` in
`test/lab.sh` and `local-sg-limit` by steps 5 and 6 of `keepalive`,
which flood R1 with groups at the limit and reload it; the Join and Hello
bullets have none.*


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
  suppression half of the same function still reads such a group set, and
  `pack_and_send_jp_message()` can still encode one, though no caller asks it
  to; what that suppression code can do, however, is nothing.  Every branch of
  it works on `rpentry->mrtlink`, the (\*,\*,RP) entry, and nothing in this tree
  ever sets it: `create_mrtentry()` returns NULL for flags that are neither
  `MRTF_SG` nor `MRTF_WC` (`src/mrt.c:884`), so the pointer read at
  `src/pim_proto.c:2959` and `:3003` is always NULL, `join_or_prune()` answers
  `PIM_ACTION_NOTHING` for it, and the hundred lines past that cannot execute.
  Measured rather than read: those lines are unreached by the whole lab suite in
  `doc/README-coverage.md`'s table, and they stay unreached with a (\*,\*,RP)
  message on the wire.  The right change is deletion, which is a separate
  question from conformance and belongs in `doc/TODO.org`.  *Check: Appendix A,
  `doc/rfc7761.txt:7567`, which is where RFC 4601's (\*,\*,RP) support was
  removed.  Test: step 4b of `crafted` in `test/lab.sh`, which sends the shape
  three ways -- addressed to R1, overheard, and as a Prune -- and asserts the
  parser walks it, builds nothing, and goes on acting on the Join after it.*
- **Sec. 4.5.6's compound Join(\*,G)+Prune(S,G,rpt) is implemented**, through
  `MRTF_RP` entries pulled into the same group set (`src/route.c:1933-1952`) and
  the RPT bit set from that flag.  The triggered half of sec. 4.5.7 beside it
  is `rpt_timers_expire()` (`src/route.c`).  *Check: sec. 4.5.6, `doc/rfc7761.txt:3927`.*
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
- **The group-to-RP mapping algorithm is the one sec. 4.7.1 writes.**
  `rp_grp_match()` (`src/rp.c:862`) takes the longest match first, then the
  highest priority, then the hash, then the higher address, which is steps 1
  to 4 with sec. 4.7.2's tiebreak.  The longest match falls out of the list
  order rather than a sort: `grp_mask_list` is ordered by masked prefix and,
  within one prefix, by mask length, and of two entries that both match a
  group the shorter one's prefix is the longer one's with its low bits
  zeroed, so the longest always comes first.  The guards that carry the
  longest match across the outer loop compare two masks in network byte
  order, which looks wrong and is not: byte-swapping permutes bits, masks of
  different lengths are nested as bit sets, and a permutation leaves a subset
  a subset, so the order survives it.  It is also invoked where the
  section says it must be, on every Join/Prune received
  (`src/pim_proto.c:2209`), and a Join(\*,G) naming a different RP than the
  mapping gives is dropped there (`:2389`).  *Check: sec. 4.7.1,
  `doc/rfc7761.txt:5534` and `:5568`.*
- **The hash function is the spec's, and so is the mask it defaults to.**
  `RP_HASH_VALUE` (`src/rp.c:40`) is the formula of sec. 4.7.2 with
  `% 0x80000000` for the mod 2^31; the multiply wrapping at 32 bits does not
  change the answer, because 2^31 divides 2^32.  Where no Bootstrap supplies
  a hash mask pimd uses `RP_DEFAULT_IPV4_HASHMASKLEN`, 30 bits
  (`src/pimd.h:128`, applied at `src/rp.c:101` and `:112`), which is the
  default the section names.  *Check: sec. 4.7.2, `doc/rfc7761.txt:5621` for
  the mask and `:5639` for the highest-value-wins rule.*
- **A static RP is advertised as if it were a candidate.**
  `create_pim_bootstrap_message()` walks `grp_mask_list`, which holds the
  `rp-address` entries alongside anything learned, so a pimd that wins the
  BSR election floods its own static RPs to the domain at priority 1 with a
  holdtime of 0xffff.  RFC 5059 has a BSR advertise the set it learned from
  Candidate-RP-Advertisements, so this is an extension rather than the
  mechanism; it is also how a static RP reaches the rest of the domain at
  all, and worth knowing before touching R1.
- **SSM group prefixes are kept out of the RP set pimd originates**, on both
  paths that could put them there: the Bootstrap builder skips a prefix in
  the range (`src/rp.c:977`), so the RP invented in S1 never leaves the
  router, and a BSR refuses a Candidate-RP-Advertisement for one
  (`src/pim_proto.c:4655`).  The receive path has no such test, and that is
  what decides S1 and S4: a Bootstrap advertising 224.0.0.0/4 maps every SSM
  group onto a real RP.
- **Rules one and two of sec. 4.8.1 are kept.**  `join_or_prune()` returns no
  action for a (\*,G) in the SSM range (`src/pim_proto.c:1463` and `:1522`)
  and the periodic builder skips any entry of such a group that is not (S,G)
  (`:2614`), so no (\*,G) Join/Prune is sent for one; nor is an (S,G,rpt)
  message, which both machines send only beside a (\*,G) and
  `rpt_see_prune()` refuses outright for a group in the range.  *Check: sec. 4.8.1, `doc/rfc7761.txt:5668` and `:5670`.*
- **Sec. 4.8.2 does not apply, and the two notes under it hold anyway.**
  pimd implements the full protocol rather than the subset, the (S,G,rpt)
  machines included, which that section lists among what an SSM-only router
  may leave out.  Of its two "treat it as" notes, the
  Keepalive Timer is restarted by arriving data like any other, sec. 4.2,
  and the SPTbit ends up set on the first packet of an SSM
  (S,G) rather than by construction: `update_sptbit()` (`src/route.c:653`),
  reached from the cache miss at `:1311`, finds `no_rpt_olist` true whenever
  the group has no (\*,G), which for an SSM group is the normal case.
  *Check: sec. 4.8.2, `doc/rfc7761.txt:5742`.*
- **The Register checksum is right on both sides.**  Sec. 4.9.3 has the
  sender cover only the first 8 bytes, which `send_pim_unicast()` does for
  `PIM_REGISTER` and only for it (`src/pim.c:403-405`), and asks a receiver
  to also accept one computed over the whole message, which
  `receive_pim_register()` does by trying the short form first and the long
  one after (`src/pim_proto.c:952-953`).  The `send_pim()` path carries a
  TODO about excluding the encapsulated packet; it is stale, no Register
  goes through that function.  *Check: sec. 4.9.3, `doc/rfc7761.txt:6225`.*
- **The dummy header of a Null-Register matches sec. 4.9.3's table field for
  field.**  Version 4, header length 5, fragment offset and More Fragments
  zero, total length 20, protocol 103, header checksum computed
  (`send_pim_null_register()`, `src/pim_proto.c:1292-1303`).  I1 was the one
  field that did not, and it is fixed.  What the receiver does with the
  table is F6.  *Check: sec. 4.9.3, `doc/rfc7761.txt:6253`.*
- **Multicast PIM leaves with TTL 1 on both platforms, although `send_pim()`
  writes 255.**  The header it builds sets `ip->ip_ttl = MAXTTL` and only a
  `RAW_OUTPUT_IS_RAW` build, which is the Linux one, replaces it with
  `curttl` (`src/pim.c:276` and `:303-304`).  Everywhere else the value in
  the header is overwritten by the kernel: `init_pim()` sets IP_MULTICAST_TTL
  to `MINTTL` (`src/pim.c:85`) and FreeBSD's `ip_output()` assigns
  `imo->imo_multicast_ttl` to every multicast datagram, IP_HDRINCL included.
  Worth knowing before "fixing" the 255, which is the value the unicast
  messages want.  *Check: sec. 4.9, `doc/rfc7761.txt:5783`.*
- **Everything pimd builds gets the encoded-address fields right.**  Family
  and type are IPv4 native, the group and source mask lengths are 32
  (`SINGLE_GRP_MSKLEN`, `SINGLE_SRC_MSKLEN`), the reserved byte carrying B
  and Z is zero, the S bit is set on every source entry ("Mandatory for
  PIMv2", `src/pim_proto.c:2907`), and a (\*,G) entry carries WC and RPT
  together with the RP as its source address, which is sec. 4.9.5.1's
  definition of one.  The entries above are about reading these fields, not
  writing them.  *Check: sec. 4.9.1, `doc/rfc7761.txt:5978` for the S bit,
  and sec. 4.9.5.1, `:6547`, for the (\*,G) entry.*
- **Sec. 4.9.5.2's fragmentation rules are implemented, including the tie-
  break.**  A group set carrying a (\*,G) Join is not split across messages,
  and where more (S,G,rpt) Prunes are pending than one message can hold, the
  numerically smallest are the ones sent (`jp_prune_keep_smallest()`, reached
  from `add_jp_entry()`, `src/pim_proto.c:2842-2864`).  That was M9.
  *Check: sec. 4.9.5.2, `doc/rfc7761.txt:6703`.*
- **A Hello with an option pimd does not know is still a Hello.**
  `parse_pim_hello()` (`src/pim_proto.c:662`) steps over an unknown option by
  its own length and forms the neighbor relationship anyway, which sec. 4.9.2
  requires; a known option of the wrong length is refused, which it does not
  forbid.  A Hello with no Holdtime option at all gets
  `Default_Hello_Holdtime` rather than being read as a goodbye.  *Check:
  sec. 4.9.2, `doc/rfc7761.txt:6189`.*
- **A Register-Stop naming source 0.0.0.0 is honoured.**  Sec. 4.9.4 allows
  the wildcard, and `receive_pim_register_stop()` suppresses every (S,G) of
  the group it is currently registering, which is RFC 7761's reading of an
  RFC 2362 message.  The group mask length in the same message is ignored
  rather than applied, as the TODO sitting in that function says; nothing
  converts it, so there is no mask to get wrong.  *Check: sec. 4.9.4,
  `doc/rfc7761.txt:6348`.*
- **The DR does not register a packet whose source does not belong to the
  interface it arrived on.**  That is a MUST in sec. 6.2, and it is met one
  layer below where it reads as though it should be:
  `send_pim_register()` only asks whether the source belongs to some
  directly connected subnet (`src/pim_proto.c:1195`), but the only thing that
  ever reaches it is a `IGMPMSG_WHOLEPKT` upcall, and the only thing that
  makes the kernel send one is a forwarding entry whose oifs hold the
  register vif, which `process_cache_miss()` creates only when the arrival
  interface is both the DR's and the one the source's subnet is on
  (`src/route.c:1264`).  A packet with a spoofed source from another subnet
  never gets that entry, so it is never encapsulated.  Worth knowing before
  moving either test: the guarantee is the conjunction, not either half.
  *Check: sec. 6.2, `doc/rfc7761.txt:7374`.*
- **A Register-Stop is only believed from the RP of the group**, which is
  sec. 6.2's next sentence and is what `check_mrtentry_rp()` enforces for a
  source-specific one and the `grp->rpaddr != reg_src` test for the RFC 2362
  wildcard.  The comment above it calls this "not in the spec"; it is, at
  sec. 6.2, and the comment is worth correcting the next time the file is
  open.  *Check: sec. 6.2, `doc/rfc7761.txt:7377`.*
- **Log output is rate limited, in the mode where it matters.**  Sec. 4.9
  asks for errors to be logged "in a rate-limited manner", and a malformed
  packet reaches `logit()` at LOG_NOTICE or LOG_WARNING on most of the
  refusal paths, so an attacker gets one line per packet unless something
  stops it.  Something does: `logit()` counts messages at the configured
  level or worse and stops passing them to syslog past `LOG_MAX_MSGS`
  (`src/debug.c:630-632`), a counter `resetlogging()` clears once a minute,
  and if the minute's budget was spent it stops syslog output altogether for
  `LOG_SHUT_UP` and says so (`src/main.c:851-873`).  In the foreground the
  limiter is bypassed and every message goes to stderr, which is what
  `-n -l debug` is for.
  *Check: sec. 4.9, `doc/rfc7761.txt:5852`.*
