This pimd is maintained at <https://github.com/ocochard/pimd>, a fork of
<https://github.com/troglobit/pimd>.  A bare issue number in an entry
below, `#93` say, is an issue of the tracker pimd was forked from; an
issue of this repository is written out in full.

[UNRELEASED][]
--------------

### Fixes
- A router that had lost the Assert election toward the RP sent its
  periodic Join(*,G) to the winner without the Prune(S,G,rpt) of the
  sources it had pruned off the shared tree, so the winner put them back
  on the LAN every period until the separate Prune arrived.  RFC 7761
  sec. 4.5.6 has them in one message.  Step 7j of `crafted` in
  `test/lab.sh`.
- A router that had lost the Assert election for a source on its upstream
  link moved its Joins away from the winner, and pruned it, whenever its
  route to the source changed to another router on the same link.  RFC
  7761 sec. 4.5.5 keeps them with the winner while the Assert holds.  Step
  7k of `crafted`.
- A router that had pruned a source off the shared tree for one
  downstream neighbour never joined that source for another neighbour
  that asked for it with a Join(S,G), where the source and the RP were
  reached through the same interface: the second neighbour received
  nothing.  RFC 7761 sec. 4.5.5.  Step 7l of `crafted`.
- A Prune(*,G) took the interface off the shared tree but not off the
  sources of the group that had an (S,G) entry, which went on flowing onto
  the pruned link until a copied timer ran out -- for good under a
  holdtime of 0xffff.  RFC 7761 sec. 4.1.6.  Step 7m of `crafted`.
- A Join(*,G) and a Prune(S,G,rpt) arriving in the same message for a
  group the router held nothing for -- what a downstream neighbour sends a
  new upstream after an RPF change -- created the group and dropped the
  prune, so the pruned source was forwarded until the next periodic
  message.  RFC 7761 sec. 4.5.3.  Step 7n of `crafted`.
- A Prune(S,G,rpt) with a shorter holdtime than the one already held for
  that source and interface replaced it, so one neighbour's short prune
  cut another's longer one short, and a finite one ended a prune held with
  0xffff.  The longer of the two is kept now, RFC 7761 sec. 4.5.3.  Step
  7o of `crafted`.
- A group moved to another RP by a new RP set left its old upstream
  router unpruned, which went on forwarding the group onto the link beside
  the new upstream until its own state aged out.  A Prune(*,G) goes to the
  old upstream now, RFC 7761 sec. 4.5.7.  Step 14b of `crafted`.
- A downstream Join whose holdtime ran out while a Prune for it was
  pending sent a PruneEcho onto the link, which only the end of the
  Prune-Pending wait itself calls for.  RFC 7761 sec. 4.5.1 and 4.5.2.
  Step 9b of `crafted`.
- A source pausing for more than 210 seconds took its (S,G) entry with
  it, together with the Joins downstream routers held for it: a Join sent
  with a holdtime of 0xffff, never refreshed, was lost for good, and one
  with a holdtime above 210 seconds between two refreshes.  The entry now
  lives as long as any Join(S,G) or Prune(S,G,rpt) on it does.  RFC 7761
  sec. 4.9.5.  Step 13c of `crafted`.
- A Prune(*,G) overheard on the upstream link was overridden only when it
  named this router's RP, so a neighbour whose group-to-RP mapping had
  moved first -- whose Prune names the new RP -- had the group pruned off
  the link under the routers still wanting it, until the upstream's own
  PruneEcho brought the override, too late.  RFC 7761 sec. 4.5.4.  Step 7p
  of `crafted`.

[v3.3.0][] - 2026-10-08
-----------------------

### Changes
- Parts of pimd are proven with the bounded model checker CBMC, by
  `test/cbmc/run.sh` and a job of the Linux CI workflow on every push: the
  wire decoders, the configuration and `pimctl` text parsers and the
  message writer read and write nothing out of bounds; the Assert election
  follows the metric order and the state machines of RFC 7761 sec. 4.6,
  tables and prose; and every message pimd builds decodes back to what was
  encoded.  Each proof is checked by broken variants of its code that it
  has to reject.  The Assert proofs found or confirmed five of the Assert
  fixes below, M23 to M27 of `doc/rfc7761-compliance.md`.
- `pimctl show mrt detail` prints each entry's upstream neighbor, the one
  its Joins go to: the routing table's, or the winner of an Assert on the
  incoming interface (RFC 7761 sec. 4.1.6).

### Fixes
- A Bootstrap group set whose RP count is zero while its fragment RP count
  is not had its RP records read as the next group set.  The checks of
  `receive_pim_bootstrap()` stepped over the records and the loop that
  installs the ranges did not, so the two walks of one message parted and
  the second installed a range and an RP the BSR never sent, out of the
  bytes of an RP address and its holdtime.  The message is walked once now,
  by a decoder the install loop reads it through, and the next set is always
  behind the records the fragment count says.  `crafted` step 31 of
  `test/lab.sh` sends such a message.
- An mtrace query's response TTL and query ID were read through the
  bitfields of `struct tr_query`, whose order is the compiler's: with clang
  on FreeBSD/amd64 (measured) the TTL came out of the query ID's last byte,
  and a multicast reply went out with that TTL -- zero for a query ID ending
  in 0x00.  Both are read at their
  offsets on the wire now, by a decoder in `src/igmp_parse.c`.
- A router that was the Assert loser on its RPF interface kept that
  state when its route moved to another interface, for up to its Assert
  Timer, 180 seconds, and read it as a loss on that interface, which had
  become a downstream one: measured, a member there was left out of the
  outgoing interfaces until the timer ran out.  RFC 7761 sec. 4.6.1 and
  4.6.2 send the state to NoInfo the moment the interface stops being the
  RPF interface, and pimd does now.  Step 9 of `assert-recover` in `test/lab.sh` moves such a route.
- An Assert without the RPT bit, arriving on the interface toward the RP,
  could make pimd the Assert loser for the whole group and move the group's
  upstream neighbour to whoever sent it, where it had no (S,G) state for the
  source the Assert named.  RFC 7761 sec. 4.6.2 lets only an Assert with
  the RPT bit move the (\*,G) machine there, and pimd now ignores the other
  kind for it.  Step 7b of `crafted` in `test/lab.sh` sends both.
- A router forwarding a source off the shared tree that saw that source's
  data on one of its outgoing interfaces held the Assert election that
  followed on its (S,G) entry rather than its (\*,G) one, as RFC 7761 sec.
  4.6.1 and 4.6.2 divide them, and having won it there kept the interface
  against any better Assert from the shared tree.  The election goes to the
  (\*,G) entry now, and a winner leaves on any Assert that beats it.
- An RP forwarding its shared tree onto a LAN where another router forwarded
  the same group sent its Asserts with an infinite metric, which is an
  AssertCancel, and lost every such election.  It asserts with the zero
  metric of its own address now, RFC 7761 sec. 4.6.3.  Step 7c of
  `crafted` in `test/lab.sh` puts it.
- A router that had lost the Assert election for a source on its upstream
  link ignored the winner's AssertCancel and went on sending its Joins for
  that source to a router that had stopped forwarding it, for up to three
  minutes.  It goes back to the routing table's neighbour at once now,
  RFC 7761 sec. 4.6.1.  Found by the CBMC proof of the Assert decisions,
  put by step 7d of `crafted` in `test/lab.sh`.
- The same router, sent the winner's Assert again at a worse metric than it
  had won with, took its Joins back to the routing table's neighbour while
  the winner went on forwarding.  It stays with the winner until the winner
  cancels or times out, as RFC 7761 sec. 4.6.1 and 4.6.2 have it.  Step 7e
  of `crafted`.
- A router whose (*,G) lost the Assert election on its link towards the RP
  went on sending the group's Joins to the router that had lost whenever it
  also held a source pruned off that shared tree: the Assert went to that
  source's entry instead.  Both now follow the winner, and stay with it
  across the periodic check of the unicast routes, which put them back on
  the routing table's neighbour.  RFC 7761 sec. 4.1.6 and 4.6.2, step 7f of
  `crafted`.
- A router that had lost the Assert election for a source it forwards off
  the shared tree renewed that loss on every Assert its winner sent for the
  group, including those that no longer named the source's own tree, and
  so went on holding the interface out long after the winner had stopped
  asserting for the source.  RFC 7761 sec. 4.6.1, step 7g of `crafted`.
- A router that had lost the Assert election for a source to a router
  that then asserted for the group from the shared tree, worse than this
  router's own metric, gave the source up and claimed the group on the
  same message.  RFC 7761 sec. 4.6.2 forbids exactly that; the second
  machine now sees the message only after the winner's AssertCancel.
- A router that lost the Assert election for a source on its upstream link
  took the source's tree as its own only once the source's data reached
  it, where RFC 7761 sec. 4.6.1 has that happen on the election itself.
  Step 7h of `crafted`.
- A router that had won the Assert election for a group on a LAN gave the
  whole group up to an Assert about a single source, such as the first
  hop router of a source on that LAN sends, and stopped forwarding every
  other source of the group there.  RFC 7761 sec. 4.6.2 has the (*,G)
  winner act on (*,G) Asserts alone.  Step 7i of `crafted`; it also made
  step 13 of `shared-lan` fail on Linux two runs in five.

[v3.2.0][] - 2026-10-01
-----------------------

### Changes
- An address a `pimd.conf` names by interface is resolved again on every
  interface scan, so `bsr-candidate`, `rp-candidate`, `autorp announce` and
  `autorp mapping-agent` may name an interface that does not exist, or has no
  address, when pimd reads its configuration.  pimd has taken an interface
  that appears under a running daemon since the `ifnew` work -- it gives it a
  VIF and applies the `phyint` lines naming it -- but these four resolved a
  name to an address exactly once, at parse time, through a table that was
  whatever the kernel had at startup.  The two candidacies then did the worst
  possible thing with the failure: `max_local_address()`, silently, so a
  router configured `bsr-candidate ng0` came up as a Candidate-BSR on the
  highest address of some other interface and stayed there until a reload.
  That is the ordinary case on anything negotiated rather than configured --
  PPP, L2TP, a tunnel, a VLAN added to a router in service -- and the only way
  round it was to start pimd from a script that polls for the address.  The
  token written in the file is kept now and resolved again from
  `rescan_vifs()`, the candidacy is held rather than misdirected while it
  resolves to nothing, and it is taken up when the address appears, follows it
  when it moves, and is given up when it goes.  `pimctl show status` reports a
  candidacy in that state as `Pending`.  A Candidate-BSR taking its role up
  mid-flight claims the election only where nobody better holds it, the
  comparison being `receive_pim_bootstrap()`'s.  Written out as an address
  rather than as a name, the four behave the same way, and the keyword written
  with no address at all still picks the highest local address once.  Steps 3
  and 10 of the `ifnew` scenario of `test/lab.sh` are the assertion
- The (S,G) Keepalive Timer is restarted by the traffic it is about, RFC 7761
  sec. 4.2 and deviation M7 of `doc/rfc7761-compliance.md`.  Every write to
  pimd's timer of that name, `entry_timer`, was a control-plane event or a
  kernel upcall, and three of those cover most of the table between them: a
  downstream neighbour's periodic Join, the Register probe loop between a DR
  and its RP, and, for an entry with an empty outgoing interface list, the
  cache miss every one of its packets raises.  What none of them covers is a
  last hop router's (S,G) whose only outgoing interface is a local member
  inherited from the (\*,G).  Nothing is joined downstream of it, nothing is
  registered, and it forwards in the kernel, so the only thing that ever
  restarted its timer was the `spt-threshold` poll calling
  `switch_shortest_path()` again -- and with `interval` longer than the 210
  second Keepalive_Period the entry aged out under a source that had never
  stopped sending, which cost no traffic, the shared tree going on forwarding,
  but made the switch to the shortest path tree oscillate with the period of
  the poll.  pimd forwards in the kernel and never sees the packet, so "on
  receipt of data" is answered the way `check_sptbit()` already answered
  Update_SPTbit: the kernel counts what it forwards and matches on the
  incoming interface of the entry holding the MFC, so a count that moved
  between two `age_routes()` passes on an entry whose incoming interface is
  RPF_interface(S) is data from S received on RPF_interface(S).  One kernel
  call per (S,G) per pass now answers the Keepalive Timer and the SPTbit both,
  in sec. 4.2's own order.  Step 9 of the `rpt` scenario of `test/lab.sh` is
  the assertion
- `find_route()` says why it refused when it is asked to create an entry, as it
  already did when it was not.  Five returns of `NULL` on the creating path --
  no group entry, no RP for the group, no source entry, no (S,G), no (\*,G) --
  were silent, so a caller that got nothing back had nothing to go on: an IGMP
  membership accepted with no forwarding state behind it looked exactly like one
  that had been forwarded, from the outside and from the logs.  One
  `IF_DEBUG(DEBUG_MRT)` line each, and it is what identified the SSM case now in
  `doc/TODO.org`
- A sanitizer report from the half of a separated pimd that parses the wire is no
  longer thrown away.  `SANITIZE=yes` in `test/lab.sh` gave each daemon an
  `ASAN_OPTIONS=log_path`, and the unprivileged half is `chroot()`ed into a
  directory that is root-owned and unwritable by design, so the runtime printed
  `ERROR: Can't open file` and died *instead of* printing its finding, while
  `check_sanitizer()` found an empty directory and reported no sanitizer output:
  every memory error in the daemon's parser was invisible to the weekly
  `sanitize.yml` run, and invisible in the way that looks like a clean result.
  There is no `log_path` now -- stderr needs no path, being open on the daemon's
  own log before either the `chroot()` or the uid drop -- and the check reads the
  logs, matching UBSan's `runtime error:` as well as each runtime's banner.  What
  the chroot still costs is the symbolizer the runtime would have to `exec()`, so
  frames from that half are addresses: the new `SAN_NO_PRIVSEP=yes` trades the
  split for a readable trace, as `COVERAGE=yes` already trades it for `.gcda`
  files, and the check prints both ways out when it sees raw frames.  Found by
  the `rp-nbr-gone` scenario, whose report was the first that had to come back
  from that half
- A process a lab scenario stops is the one it started.  `test/lab.sh` and the
  two interop scripts started a command inside a jail or a network namespace
  through a shell function and kept `$!`, which names the shell's fork of the
  function body rather than the command, so every `kill` stopped an
  intermediate and left the command running: on Linux a receiver went on
  holding its kernel join, and went on answering queries for a membership the
  step had just withdrawn, until its own `-W` ran out.  Nothing asserted that a
  process was gone until the `altnet` step that takes a boundary through a
  membership going away and coming back, which withdraws one with an IGMPv2
  leave and waits for it to expire -- R3 took the leave and sent the
  group-specific query, the receiver of the step before answered it, and the
  membership stayed.  `box_bg()` in `test/lab-linux.sh` and
  `test/lab-freebsd.sh`, and `jbg()` in `test/freebsd-interop.sh`, which has a
  `jrun()` of its own, background a subshell that `exec`s, `ip netns exec` and
  `jexec` execing in turn, so `$!` is the command itself -- the chain
  `box_daemon()` already documents for the PID file it writes.  46 call sites,
  and not one of them was failing on FreeBSD, whose `/bin/sh` execs the single
  command of a function body, which is the accident this stops relying on
- An `altnet` scenario in `test/lab.sh` for the two `phyint` keywords that say
  something about addresses rather than about PIM, neither of which any
  scenario wrote into a `pimd.conf` before: `altnet`, a subnet the interface
  has no address in and pimd treats as being on the link anyway -- what the
  `alias` scenario gets from the kernel, said in a configuration file instead
  -- in each of the three forms the keyword has, a length in the token, a
  `masklen` word after it, and neither, which means the interface netmask; and
  `scoped`, the RFC 2365 forwarding boundary, on the receiver's link, where a
  group inside it is joined and not forwarded, which is what separates it from
  `igmp-accept-groups`, where the report is refused and no membership exists at
  all.  Five malformed altnets and five malformed boundaries beside them, since
  a configuration file is operator input and every arm that warns and carries
  on was a line nothing had ever run: `parse_phyint()` was the largest
  unreached block of `src/config.c` in `doc/README-coverage.md`'s table, and
  `doc/TODO.org` has twice asked for work on a parser nobody could watch
  running.  What says an altnet was installed rather than only parsed is a
  neighbour -- `find_vif_direct()` walks a VIF's altnets before it asks the
  kernel, so a Hello from inside one is accepted and one from outside every
  altnet is not -- and that step runs last, a Hello from an address above R1's
  own making its sender the DR of the link and stopping everything else in the
  scenario
- `test/pimsend.c` can cut a message short, `-t LEN`, and the `crafted`
  scenario asserts what the Join/Prune parser does with one.  Every
  `receive_pim_*()` that reads past its header tests the length it was handed
  first, and nothing had ever reached one of those tests: pimd builds whole
  messages, so a lab of pimds cannot ask, and `-x` flips bytes without
  shortening.  The cut is made before the checksum rather than after, so the
  short message carries one that is correct over what is left of it and dies
  at the length test instead of ahead of it.  Two cuts are asserted, because
  two files make the test -- `pim.c` refuses a message with no room for the
  PIM header at all, the Join/Prune parser one with no room for the fields
  `PIM_JOIN_PRUNE_MINLEN` names -- with the well-formed Join beside them as
  the control.  This is the bound whose absence in `receive_pim_assert()` the
  security notes of `.github/CONTRIBUTING.md`'s neighbourhood are written
  about; it is now asserted rather than read
- Three more `crafted` steps, all of them shapes no pimd sends: a (\*,\*,RP)
  Join/Prune, which RFC 7761 removed (Appendix A) and which this tree still
  parses -- the step asserts the parser walks it, builds nothing from it and
  goes on acting on the next Join, since the (\*,\*,RP) code behind it turns
  out to be unreachable, `create_mrtentry()` never making the entry every
  branch of it works on (written up in `doc/rfc7761-compliance.md` and
  `doc/TODO.org`); an (S,G) Prune on a link with one PIM neighbour, the half
  of RFC 7761 sec. 4.5.1 that excuses the Prune-Pending Timer and the
  PruneEcho where there is nobody to override and nobody to echo to, step 9
  beside it being the two-neighbour half; and a shared tree Prune for a group
  in the SSM range, the other direction of the sec. 4.8.1 rule 4 refusal the
  scenario already asserted for a Join, with a Prune outside the range as its
  control
- `pimctl show status` reports how long the last pass of `age_routes()` took
  and the longest one since start-up, in microseconds.  That pass walks every
  group and every (S,G) once per 5 second tick, which `doc/TODO.org` has long
  guessed is "very unefficient if the routing table becomes very large"; the
  daemon measures it for itself now, so an operator asking whether a router is
  spending its time ageing routes has the answer on the router.  Measured with
  the new `scale` scenario: 29 us at 200 entries, 95 us at 1000, 282 us at
  3000 and about a millisecond at 10000 -- linear, and 0.03% of the tick that
  schedules it, which retires that entry
- `autorp listener` passes the two Auto-RP groups on, which is what makes the
  feature work in a domain more than one hop wide.  Auto-RP assumes somebody
  floods 224.0.1.39 and 224.0.1.40 to every router (sec. 3.3) and says nothing
  about who; pimd has no dense mode, so without this a mapping agent adjacent
  to the candidate RPs and to the routers works and anything wider does not.
  A datagram that arrives on either group is now re-sent out of every other
  PIM interface with its TTL decremented, which is what IOS spells `ip pim
  autorp listener`.  Off by default: it puts the router in the forwarding path
  for traffic nobody asked it to carry.  Three things bound it -- those two
  groups only, a TTL that survives the decrement, and never back out of the
  arrival interface -- and a relay keeps the source address it arrived with,
  which is where the agent election of sec. 3.2 and the "Agent" column of
  `pimctl show autorp` read the agent.  That takes a raw socket, so under
  privilege separation the parent opens it
- `phyint ... igmp-accept-groups PREFIX` says which multicast groups a host on
  that link may join.  A membership report for any other group is ignored: no
  group state, no shared tree, nothing a host on a stub LAN can make this
  router hold by asking.  An empty list accepts every group, so a
  configuration without the keyword behaves as before.  Never filtered:
  224.0.0.0/24, the link local control groups, and Auto-RP's 224.0.1.39 and
  224.0.1.40, which every router in a domain running Auto-RP joins -- a list
  that refused a neighbour's membership for those would refuse to carry that
  protocol through this router.  This is not `scoped`, the RFC 2365 boundary beside it on the
  same line: that says where the traffic may go and drops the packets while
  keeping the membership.  No RFC asks for this one -- it is the control other
  implementations spell `ip igmp access-group` -- and `pimctl show igmp
  interface` has an `Accept` column counting the ranges in force per interface
- `crp-accept-from` and `crp-accept-group` in `pimd.conf` say whose Candidate-RP
  Advertisements a bootstrap router acts on, and which group ranges it carries
  out of them.  RFC 5059 sec. 4.1 recommends both: the message is unicast and
  needs neither a neighbour relationship nor a place on one of the BSR's links,
  so without them the RP set of the whole domain is state any host able to
  reach the BSR can create, and the BSR writes all of it into every Bootstrap
  the domain then believes.  `rp-set-limit` bounds how much of it a stranger
  can make; these say who the stranger may be.  Either list empty accepts
  everything, as `register-accept-from` does, so a configuration that says
  nothing behaves as before.  A range has to fall *inside* a `crp-accept-group`
  prefix, so a list of 239.1.0.0/16 refuses a candidacy for all of 224.0.0.0/4;
  refused ranges are dropped one at a time and the rest of the advertisement is
  kept.  `pimctl show status` lists both, and a refusal is logged once per
  configuration
- A `group-prefix` of an `rp-candidate` may carry a `priority` of its own, so
  that one router is the preferred RP for some groups and the last resort for
  others.  A range written without one takes the priority of the
  `rp-candidate` line, whichever order the two keywords appear in.  RFC 5059
  sec. 4.1 has the bootstrap router keep a priority per RP per group range
  while sec. 4.2 gives a whole Candidate-RP-Advertisement one priority, so
  pimd now sends one advertisement per priority in use; a BSR that is not
  pimd sees several ordinary advertisements from the same candidate.
  `pimctl show status` lists the ranges this router advertises and the
  priority of each, which nothing said before a BSR had them.
- A Candidate-RP-Advertisement always names at least one group range now.  A
  candidacy with no `group-prefix` line is one for the whole of 224.0.0.0/4,
  and pimd used to say so by sending a Prefix Count of zero -- which RFC 5059
  sec. 4.2 says a C-RP MUST NOT send, and which only another pimd read as the
  default range.  A foreign BSR is within its rights to drop such a message,
  and the shipped `pimd.conf` is exactly that configuration.  The default
  range is one list entry like any other now, so the count cannot be zero by
  construction; the receiving side still takes a zero count as the default
  range, an older pimd being on the other end of it
- `pimctl -j` prints the reply as JSON, for a script that would otherwise
  read columns.  Each table is an array of objects named after the table,
  `show status` is one object of the same values, and a key is the column
  heading lowercased with runs of anything but a letter or a digit turned
  into one underscore -- `.interface[].dr_address` for the "DR Address"
  column.  A value this router has not got is `null` where the table prints
  "N/A".  Every table is declared once now, in the function that fills it in,
  and rendered by either of two writers, so a column added to the text form
  is in the JSON by construction and the heading is read off the first row
  rather than written out beside it.  `show compat`, a text format from before
  `pimctl` existed, has no JSON form and answers `-j` with an "error"
  member saying so; the `detail` half of `show mrt` has none either, its
  per-interface maps and timers being a block rather than a table, so
  `show mrt detail -j` is the table without them.  Three things about the
  text form changed with it: `show rp` names the group range on every row
  of it rather than only on the first RP of a range, the secondary
  addresses of `show neighbor detail` name their interface and say
  "secondary" in the Mode column, with "N/A" for the priority and uptime
  a secondary has not got, and the ':' of `show status` moved three
  columns right, one past the longest label in the listing, so that every
  one of those lines has a space before the colon
- `phyint ... passive` runs IGMP on an interface and no PIM: no Hello of this
  router's goes out there and no adjacency is formed with one that arrives, so
  a Join/Prune, an Assert or a unicast Bootstrap from that link is refused for
  want of a neighbour.  Everything else is unchanged -- memberships are
  learned, traffic is forwarded, a source on it is registered -- which is what
  separates it from `disable`.  What it is for is a stub LAN of hosts, where a
  Hello every thirty seconds is noise and an adjacency with whatever answers it
  is a way in.  `pimctl show interface` reports the state as `Passive`.  The
  flag it sets, `VIFF_PASSIVE`, had been defined and unused since the tree was
  imported, meaning "passive tunnel" in mrouted
- `rp-set-limit` in `pimd.conf` caps the group ranges the RP set may hold, the
  way `autorp-limit` caps Auto-RP mappings and for the same reason: the state
  is a stranger's to create.  Ranges beyond it are refused and the fact is
  logged once, and `pimctl show status` reports "RP set group ranges" as a
  count against the limit.  Default 1024, which is well inside what one
  Bootstrap message can carry.  It counts ranges, and a range holds up to 255
  RPs, so the ceiling is the limit times 255 group-to-RP entries at about 180
  bytes each -- some 44 MB at the default, against 40 kB for a domain of fifty
  ranges with four RPs apiece.  `man pimd.conf` has the arithmetic
- `pimctl show igmp groups` has a version column, the compatibility mode of
  each group rather than of the interface: an older membership report puts
  one group back a version without touching the others, and a timer of its
  own brings it forward again, which nothing else reported
- pimd separates its privileges.  It runs as two processes now: a small
  privileged parent that owns the descriptors and makes the calls the kernel
  asks root for, and an unprivileged child, running as `nobody`, that does
  everything else -- every parser, every timer, every state machine, every
  byte that arrives off the wire.  A helper process rather than a `setuid()`
  once everything is open, because the kernel checks the caller on every call
  and not once on the socket: FreeBSD runs `priv_check(PRIV_NETINET_MROUTE)`
  in `rip_ctloutput()` for every `MRT_*` setsockopt and in `X_mrt_ioctl()` for
  `SIOCGETVIFCNT` and `SIOCGETSGCNT`, and Linux checks `CAP_NET_ADMIN` the same
  way, so a child that dropped root could not add a VIF or change an MFC even
  holding the mrouter socket it was handed.  On by default; `--no-privsep`
  gives back the single root process, and `-U USER[:GROUP]` (`--user`) names
  the user.  The default is `nobody`, which every supported system has, so
  nothing has to be created before pimd will start; `configure
  --with-privsep-user=NAME` builds with another, which a packager who ships a
  user of pimd's own should do, two daemons under one user id being able to
  signal and trace each other.  A user that does not exist is a start-up
  error naming `--no-privsep` rather than a fallback to somebody else's
  account.  `-p` is still `--pidfile`, and the PID file names the parent,
  which is the process a SIGHUP has to reach
- The unprivileged half runs under a seccomp-bpf filter on Linux, an
  allowlist of the syscalls the event loop makes with
  `SECCOMP_RET_KILL_PROCESS` for everything else and for any architecture
  but the one it was built for, and `PR_SET_NO_NEW_PRIVS` beside it.  There
  is no sandbox on the BSDs: Capsicum was written for this and taken out
  again, because `kern_sendit()` refuses every `sendto()` that carries a
  destination address and `kern_connectat()` every `connect()`, so a daemon
  that sends to neighbours, RPs and a group at a time cannot transmit from
  inside capability mode at all -- it comes up, answers `pimctl`, and
  silently sends nothing.  `pimctl show status` says which sandbox is in
  force, or that there is none
- The unprivileged half is also confined to an empty directory with
  `chroot()`, before it stops being root and can no longer do it.  It costs
  nothing, because by that point there is no path left for it to want: the
  configuration reaches it as a descriptor the parent opened, the PID file
  and the pimctl socket belong to the parent, and `syslog(3)` is a message
  to it.  What it buys is `open(2)` by path taken away from whatever gets
  into a parser, which on the BSDs -- where the sandbox above cannot be had
  -- is the only thing that does.  `/var/empty` by default,
  `configure --with-privsep-chroot=DIR` to move it and
  `--without-privsep-chroot` to skip it; the directory is created if it is
  missing and refused if anyone but root may write to it.  A core dump of
  the unprivileged half goes with it, `--without-privsep-chroot` or
  `--no-privsep` being how to get one back
- Every log line is now written by whichever half owns the log: the
  unprivileged one renders the message and the privileged one puts it where
  it goes, `log_emit()` in `src/debug.c`.  That is not tidiness.  A
  chroot'ed process has no `/etc/localtime`, and glibc retries that open on
  every `localtime()` call rather than giving up once, so the first line
  logged after the seccomp filter went up -- where `open` is not on the
  allowlist -- killed the daemon with `SIGSYS`, and it died before it could
  say so.  One process stamping every line also means one timezone in the
  log instead of the parent's local time beside the child's UTC.  The
  message crosses rendered and is logged with `%s`.  It crosses blocking,
  which is not a preference: a unix `SOCK_SEQPACKET` socket on FreeBSD is
  not `PR_ATOMIC`, so a non-blocking send may write part of a record, and
  the next message landing on the fragment puts the two halves permanently
  out of step.  A slow log can therefore throttle the daemon -- as it
  already does in a pimd that writes the line itself
- `configure` probes a set of warning and hardening flags and applies what
  the compiler takes, to every binary and to the `lib/` replacements rather
  than to `pimd` alone as the old `pimd_CFLAGS` did.  The warnings are the
  set this tree is silent under, `-Wformat=2` and `-Wpointer-arith` among
  them; the hardening is `_FORTIFY_SOURCE`, `-fstack-protector-strong`,
  `-ftrivial-auto-var-init=zero`, `-fno-strict-aliasing`, PIE and
  RELRO/BIND_NOW.  `--disable-hardening` drops the second half,
  `--enable-werror` turns warnings into errors and is off by default, on in
  both CI workflows.  Probed rather than hardcoded because this builds with
  gcc and with clang on Linux, FreeBSD, NetBSD and DragonFly
- `-Wshadow`, `-Wmissing-prototypes` and `-Wmissing-variable-declarations`
  joined that probed set, and what they found is fixed rather than silenced:
  everything file-local is `static` now -- the `parse_*()` of `config.c`, the
  `cmds[]` table of `ipc.c`, the timers and the saved route entries of
  `route.c`, the routing socket scratch of `routesock.c`, the whole of
  `test/mping.c` -- `curttl` and `g_rp_hold` are declared in `src/defs.h`
  instead of by an `extern` copied into each user, the `lib/` replacements
  take their prototypes from the same header their callers do, and the
  `next` of `FREE_MRTENTRY()` no longer shadows the caller's own.  The dead
  declarations and variables that `-Wno-unused` had been hiding are gone
  with them.  Found by building with clang's `-Weverything`, which is not a
  set to build under, only to read
- FreeBSD needs no `gmake` to build this.  The tree is GNU autotools, but
  what automake generates is portable make: no GNU-only syntax in any
  generated Makefile, and `configure` probes for the one directive the two
  makes spell differently, the dependency file `include`, falling back to
  the BSD spelling or to no dependency tracking.  Base system `make` runs
  the build, `make check`, `make install`, `make dist` and `make
  distcheck`, the last a VPATH build from a read-only source directory.
  `README.md` and `doc/INSTALL.md` said otherwise, and the FreeBSD CI
  workflow installed the `gmake` package and used it, so the build path
  every FreeBSD user takes was the one never tested; it runs base `make`
  now, with GNU make covered by the Linux workflow
- The sanitizer run of `test/lab.sh` is automated, in
  `.github/workflows/sanitize.yml`: every scenario against a pimd built
  `-fsanitize=address,undefined`, weekly on Linux and in a FreeBSD VM, and on
  demand through `workflow_dispatch`, which takes a scenario list and a knob
  for the leak check.  The FreeBSD job is the only sanitizer coverage
  `routesock.c` and the `kern.c` BSD branches get, the Linux one compiling
  `netlink.c` in their place, and it honours no leak knob, LeakSanitizer being
  Linux only.  `SANITIZE=yes` has been in the script since v3.0.0 and found
  the reload use-after-free of `c721f76` and the undefined shifts of
  `8b0c103`, but nothing ran it unless someone remembered to, so a regression
  of either would have reached a release green.  The tree it builds is
  `--disable-hardening` with `-fno-strict-aliasing` put back by hand:
  `-ftrivial-auto-var-init=zero` zeroes precisely the stack residue a short
  packet read would otherwise show, `_FORTIFY_SOURCE` wraps the calls ASan
  interposes on, and the aliasing flag is in that set without being hardening
- `gcc -fanalyzer` runs on every push, as the `analyzer` job of
  `.github/workflows/ci-linux.yml`.  It walks each function's execution paths
  at compile time rather than matching patterns over its text, and it costs
  seconds -- the whole tree in under five at `-j3` -- so it is a per-push job
  and not another scheduled one.  `--enable-werror`, so a new finding fails
  the job instead of scrolling past; `-Wno-analyzer-too-complex`, that one
  being the analyser saying it gave up on a function rather than anything
  about the daemon.  gcc only: clang's side of the same question is
  `scan-build`, which is not here yet.  It found one leak on its first run,
  below
- CodeQL runs on every push and every pull request,
  `.github/workflows/codeql.yml`, over a database built from a real compile of
  the daemon and with the `security-extended` suite rather than the default
  one.  It is a third analyser and not a spare: `rules/security.cocci` matches
  patterns somebody wrote down, Coverity is interprocedural but runs weekly
  because its free tier caps submissions, and this is dataflow and taint over
  the whole program, reported on the diff that introduced it -- which for a
  daemon whose entire input is packets off the wire is the question worth
  asking before a merge rather than after one.  It analyses what the Linux
  build compiles, so `routesock.c` and the BSD branches of `kern.c` are not in
  it -- not for want of a FreeBSD job, `ci-freebsd.yml` building that half in a
  VM on a Linux runner, but because CodeQL builds its database by tracing the
  compiler and has no FreeBSD CLI to do it with inside that guest.  Those files
  keep the labs and the sanitizer VM as their only coverage
- New `--enable-coverage`, `test/coverage.sh` and
  `.github/workflows/coverage.yml`: which lines of the daemon the tests reach,
  as a number rather than as a reading of the sources.  The knob puts
  `--coverage` in the probed flags -- fatally rather than silently, a build
  that lost it running the whole suite and measuring nothing -- and drops the
  hardening set with it, `_FORTIFY_SOURCE` wanting the optimiser that the
  `-O0` a line count needs takes away.  The script runs nothing itself: it
  reads the counters a run left behind and prints a table sorted by unreached
  lines, with the uncovered ranges per file beside it, which is what tells a
  file at 40% that is half a parser nobody drives from one that is a large
  error path.  `COVERAGE=yes` is the lab's side of it.  Two builds and two
  tables rather than one number, `--enable-fuzz` implying
  `--disable-exit-on-error`: a daemon that carries on past `logit(LOG_ERR)`
  is not the daemon `test/lab.sh` asserts against, so the corpus replay of
  `make check` cannot share its tree.  Nothing fails on a number; what the
  measurement is for is deciding which test to write next, and it settled
  three arguments on sight: the lab suite reaches 67.3% of the 11442
  instrumented lines of `src/` and `lib/` and the corpus replay a third of
  its own build, `dvmrp_proto.c` is reached by nothing, `trace.c` by the
  fuzz corpus alone and by no lab scenario, and what `config.c` leaves
  behind is 526 mostly single lines -- allocation failures, `LOG_ERR` arms
  and keywords no scenario writes.
  `doc/README-coverage.md` has the recipe and the three things the number
  cannot see: the unprivileged half of a separated daemon (a `.gcda` is an
  `open(2)` the seccomp filter kills and a path the `chroot()` removed, so
  the scenarios run `--no-privsep` and the `privsep` scenario, which keeps
  the split, reports only its parent), a daemon SIGKILLed on purpose by
  `restart_pimd()`, and whichever of `routesock.c` and `netlink.c` the
  measuring host does not compile

- New `--enable-fuzz`, and `test/fuzz/`: the pimd.conf parser called
  in-process with generated input, under the sanitizers.  `fuzz_config`
  hands bytes to `config_phyints_from_file()` and `config_vifs_from_file()`
  at tens of thousands of executions a second, and `fuzz_config_replay` is
  the same harness over files, which `make check` runs across
  `test/fuzz/corpus/` -- no clang, no root, no network -- so every input a
  run turns up and every crasher it produces stays asserted once committed.
  `TESTS` was empty before this and `make check` ran nothing; in a build
  without `--enable-fuzz` it still does.  The knob implies
  `--disable-exit-on-error`, `logit(LOG_ERR)` calling `exit(-1)` being a
  crash as far as a fuzzer is concerned, and it adds
  `-fsanitize=fuzzer-no-link` to the probed flags so that the daemon's own
  objects carry the coverage instrumentation: with it a run reaches 730
  edges of `config.c`, without it 7, at the same speed and looking just as
  healthy
- New `fuzz_pim` harness, the wire parsers in process: libFuzzer hands one
  PIM message to `accept_pim()` and so to whichever `receive_pim_*()` it
  dispatches to, some ten thousand times a second under
  `-fsanitize=address,undefined`, on a router the harness builds first --
  two interfaces, three neighbours, a DR, an RP set, a BSR candidacy, a
  (\*,G) and an (S,G) -- and tears down again between inputs.  This is where
  the assert bug of `receive_pim_assert()` and V1's unbounded
  `receive_pim_register_stop()` parse were: the only things that put wrong
  messages in front of those parsers before this were the `crafted`
  scenario, one named field at a time, and the `fuzz` scenario, five hundred
  mutants per type over a real network with jails, root and a kernel.  Its
  input is one message and nothing else, byte for byte what `pimsend -o`
  writes and `pimsend -b` sends, so a crasher goes on the wire against a
  live daemon and a mutant that killed one in a lab becomes a corpus entry.
  The RPF lookups are answered by a small fixed routing table of the
  harness's own (`test/fuzz/mrib.c` defines `k_req_incoming()`, so neither
  `netlink.c` nor `routesock.c` is linked), which is what keeps an input's
  answer the same on every machine.  `make check` replays `corpus/pim/`
  through `fuzz_pim_replay` the way it already did the config corpus, and
  `FUZZ_DEBUG=1` puts the daemon's logging back for the one question a
  silent harness cannot answer: whether the message reached a parser at all
- New `fuzz_igmp` harness, the other socket: one IP packet to `accept_igmp()`
  and so to IGMP itself (`igmp_proto.c`, where the v3 report's record and
  source counts are the sender's to choose and `IGMP_MAX_SOURCES` is enforced
  in the middle of the walk), to mtrace (`trace.c`, where the copy bound of
  `0e7e7bc` was), and to the kernel upcall path of `route.c` -- which is the
  one worth having.  An upcall arrives on that socket with an IP protocol of
  zero and is read as a `struct igmpmsg`; V5 and V6 of
  `doc/rfc7761-compliance.md` were both there, an upcall read for more than
  had been delivered and a vif index out of one used to subscript `uvifs[]`
  unbounded, and both were found by reading rather than by running anything.
  The input is the IP packet rather than the message, since the protocol byte
  and the header length are what accept_igmp() reads first and synthesizing
  them would put the upcall path out of reach; `igmpv3 -o` writes seeds of
  that shape and the three upcall seeds are committed as the bytes they are
- pimd learns RPs over **Auto-RP** now, the RP discovery mechanism Cisco
  published in 1998 (`doc/pim-autorp-spec01.txt`) and which IOS, NX-OS and
  FRR speak: it listens on 224.0.1.40, UDP port 496, for the mapping
  messages an agent sends, and puts what it hears in the same RP set the
  bootstrap mechanism fills.  `pimctl show rp` says which of the three
  sources each row came from in its `Type` column -- `Static`, `Dynamic`
  for the BSR's, `Auto-RP` -- and `pimctl show autorp` says which agent a
  mapping came from and how long it is still believed.  `autorp discovery
  disable` in `pimd.conf` turns it off
- pimd plays the other two Auto-RP roles as well.  `autorp announce ADDR`,
  with an `autorp group-prefix GROUP [masklen LEN] [deny]` line per range,
  makes it a candidate RP announcing itself to the mapping agents every
  interval -- and `deny` is the one thing Auto-RP can say that a Bootstrap
  cannot, an RP naming the groups it will *not* serve.  `autorp
  mapping-agent ADDR` makes it the agent: it caches what the candidates
  announce, resolves the conflicts the way sec. 3.2 asks (different lengths
  coexist, the same prefix goes to the higher address, a deny beats a
  positive prefix of the same length, and a prefix one of the same RP's own
  shorter prefixes covers is left out), and sends the result to every
  router every interval
- The one election Auto-RP has, sec. 3.2: an agent that hears a mapping
  message from a higher address stops sending its own, and speaks again
  three intervals after that agent goes quiet.  The address compared is the
  one the datagram came from, so an agent with several interfaces is a
  different address on each and which of them wins depends on the link the
  other agent is on -- which `pimctl show autorp` says out loud, naming the
  agent it gave way to
- What pimd does *not* do is flood the two well-known groups: the
  specification assumes a dense mode carries them (sec. 3.3) and this
  daemon has none.  Both messages go out of every PIM interface instead, so
  a domain whose agent is adjacent to the candidate RPs and to the routers
  works as it is, and a wider one needs the groups carried some other way.
  That is the one piece of `aidd_docs/plans/autorp.md` still open
- A configured `rp-address` beats an Auto-RP mapping for the same groups,
  which sec. 8 needs as well: the two Auto-RP groups themselves must not be
  something a mapping can take away.  And a *negative* prefix -- a deny --
  means "these groups are dense mode" in the specification, which pimd does
  not have; it is read as "no RP for these groups", final on the longest
  match even where a shorter positive prefix covers the group (sec. 6,
  rule 1)
- New `autorp-limit`, default 1024, capping the mappings Auto-RP may make
  this router hold.  Nothing authenticates a mapping message and one
  datagram can name 255 RPs with 255 group prefixes each, so this is a cap
  on state somebody else creates, like `rpt-prune-limit` and its
  neighbours; `pimctl show status` has the count, and the refusal is logged
  once
- New `fuzz_autorp` harness over the new parser, with a corpus of its own,
  and `test/autorp.c`, which builds one Auto-RP message with every field
  that can be got wrong exposed as an option -- including an RP count and a
  group count that do not match what follows.  `-o FILE` writes the payload
  instead of sending it, which is what seeds the corpus, and `-b FILE`
  sends a file verbatim, which is how a crasher goes back on the wire
- New `autorp-agent` scenario in `test/lab.sh`, the same protocol with pimd
  in every role: R1 announces itself, R2 resolves and tells the domain, R3
  two hops away learns the RP.  The resolution rules are asserted on the
  listener rather than on the agent's own bookkeeping -- the /16 inside an
  announced /8 does not arrive, the deny inside that same /8 does, a group
  under the deny gets no shared tree and one beside it does -- and then a
  second agent is configured so that the lower address falls silent while
  the higher one keeps sending
- New `autorp` scenario in `test/lab.sh`: ED1 plays the mapping agent with
  `test/autorp`, so that the parser meets messages pimd did not write, and
  R1 has to learn a mapping, refuse an
  announcement, leave the groups under a deny without an RP while serving
  the ones beside it, keep its configured RP against a mapping for the same
  range, age a mapping out when the agent goes quiet, stop at
  `autorp-limit`, and forget all of it across a reload
- `rp_grp_entry_t` records which mechanism gave it the mapping rather than
  a `is_static` flag.  The rule it stands for has not changed -- only the
  BSR's own entries are the BSR's to overwrite and to collect, RFC 7761
  sec. 4.7 -- but with a third source a flag could no longer say it, and
  the `Type` column of `show rp` had been reading it off the holdtime
- The fuzz harnesses run under MemorySanitizer as well, in a `msan` job of
  `ci-linux.yml`: every corpus replayed and a minute of hunting each, on
  every push.  MSan answers a question no other checker in this tree does
  -- "was this value ever written?" rather than "did this read something it
  should not have" -- which is the shape deviations V5 and V6 of
  `doc/rfc7761-compliance.md` had and which ASan is happy with, the bytes
  being inside a live allocation.  A build is one sanitizer or the other,
  so it is a job of its own, Linux and clang only.  The instrumented libc
  MSan usually wants is not needed here: the harnesses reach glibc through
  the interceptors its runtime ships and call nothing that has none
- `test/fuzz/router.c` poisons the tail of each receive buffer for MSan the
  way it already did for ASan, through one `fuzz_poison()`.  Without it the
  boundary would not exist in an MSan run at all -- the buffers are
  `calloc()`ed, so every byte past the packet is a defined zero and a
  parser reading past a short message reads zeroes nobody objects to
- New `assert-preference` in `pimd.conf`, which says where the metric
  preference of a PIM Assert comes from.  RFC 7761 sec. 4.6.3 wants the
  administrative distance of the routing protocol that provided the route,
  and `assert-preference rib` is that: the kernel is asked which protocol
  installed the route -- `rtm_protocol`, which netlink carries on Linux and
  on FreeBSD and a PF\_ROUTE socket carries nowhere -- and pimd advertises
  the distance that protocol is conventionally given, 0 connected, 1
  static, 20 BGP, 90 EIGRP, 110 OSPF, 115 IS-IS, 120 RIP, which are the
  numbers an Arista or a Cisco on the same LAN advertises for the same
  route.  A route whose protocol the kernel does not name, a protocol with
  no conventional distance, and every route at all on a routing socket
  build, keep the `distance` of the interface as before.  `pimctl show
  status` says which of the two is in force beside the RPF backend it
  depends on.  Half of deviation M4 of `doc/rfc7761-compliance.md`, the
  other half of the assert metric, whose first field this is: sec. 4.6.3
  compares the preference before it ever looks at the metric, and between
  two pimds it was 101 on both, so that comparison had never decided
  anything
- The default is `configured`, which is what pimd did before, and that is
  deliberate rather than caution: a router that derives its preference
  beats one that cannot before either metric is read, and on FreeBSD the
  difference between the two is a `configure` flag rather than a different
  operating system.  Two routers on one LAN, same routing table, different
  build, and the election would go to whichever was built which way.
  Deriving it is a domain-wide decision, and the keyword is how a pimd.conf
  makes it
- Step 13 of the `shared-lan` scenario in `test/lab.sh` asserts it, twice
  and in both directions, with the metrics left equal: the route to the RP
  is labelled with the protocol that is to look as if it installed it, the
  loser of the moment is given a better distance, and the LAN has to change
  hands -- against the address, which is the only reason the other router
  held it.  It needs a kernel whose routes carry a protocol and a netlink
  build to read it, so it skips itself on the BSDs and on a routing socket
  build and says which
- The `rib` sub-case of `assert-lan` in `test/freebsd-interop.sh` puts the
  same number in front of an Arista vEOS, which is the only implementation
  on any wire in this tree that derives its own: R3 reaches the source over
  a static route and derives 1 against the Arista's 100, while the
  `default-route-distance 150` in its own pimd.conf says otherwise -- and
  the `arista-wins` sub-case beside it is the control, the same 150 with no
  `assert-preference` line, where the Arista takes the LAN.  It asks
  `pimctl show status` whether the keyword took before it reads the
  election, and skips itself on a build whose RPF backend cannot name the
  protocol that installed a route
- New `fuzz_ipc` harness, over the last parser in this tree that had none:
  one pimctl command to `ipc_handle()`, the handler `ipc_init()` registers
  with the event loop, across a UNIX socket of the harness's own with a
  connected client per input, some fifty thousand a second under
  `-fsanitize=address,undefined`.  It is the least dangerous of the four --
  the socket is bound under `umask(0077)`, so the peer is already root --
  and the dispatch is the least of it: what reads the command is
  hand-written pointer work, the prefix match of `ipc_read()` against
  `cmds[]`, the `memmove()` in `strip()` and the backwards walk in
  `chomp()`, whose bound is there because without it a command of nothing
  but newlines writes its way off the front of the buffer.  An input is the
  bytes a client writes and nothing else, so the corpus is text a person can
  read and a crasher goes back at a running daemon with `nc -U`.  The router
  the `show_*()` print is built once rather than per input, which holds only
  while no command adds protocol state, and `FUZZ_DEBUG=1` prints the reply
  rather than a log, `ipc.c` logging nothing at all
- `ipc_handle()` is no longer `static`, for the reason `accept_pim()` and
  `accept_igmp()` are not: it is where a command meets the table it is
  matched against, and a harness reaching past it would keep a copy of that
  match, of the `detail` argument and of the dispatch
- The router the two message harnesses run their parsers inside is shared
  now, in `test/fuzz/router.c`: two interfaces, three neighbours, a DR
  election this router wins on one link and loses on the other, an RP set
  with one range of its own and one a neighbour is the RP for, a (\*,G) and an
  (S,G), built per input through the daemon's own receive path and torn down
  again.  Both halves of that are load bearing and were measured rather than
  assumed: with every neighbour at the default DR priority this router lost
  both elections, which left `send_pim_register()` and the register side of
  `process_cache_miss()` unreachable, and with only its own RP range every
  Register was refused before the state it would create.  The `INITED` line
  of a hunt is where that shows -- 2651 edges from the PIM seeds and 2828 from
  the IGMP ones, before a single mutation
- The fuzz harnesses poison the receive buffer past the end of each packet
  under ASan, so that a parser reading past the message it was handed is a
  use-after-poison report rather than a read of stale bytes in the same 128K
  allocation.  V5 above is that bug, and no hunt of any length would have
  seen it otherwise
- `igmpv3` takes `-o FILE`, which writes the packet it would have sent, IP
  header and all, instead of sending it: no socket, no root, and a seed for
  `fuzz_igmp` built by the same code that builds what goes on the wire
- `accept_igmp()` is no longer `static`, for the reason `accept_pim()` is not:
  it is where the daemon decides whether a packet is a message or a kernel
  upcall, and a harness that copied that decision would keep a copy of it
- `accept_pim()` is no longer `static`.  It is the one entry point that does
  what `src/pim.c` guarantees a parser -- the IP header bounds, the version,
  the destination table of RFC 7761 sec. 4.9 -- and the harness calls it
  rather than carrying a copy of those checks that would fall out of step
- `pimsend` takes `-o FILE`, which writes the message it would have sent
  instead of sending it.  No socket, so no root and no `-i` either, and `-x`
  applies first: a corpus seed, or a mutant, built by the same code that
  builds what goes on the wire
- `fuzz_config` no longer grows by an entry of the static RP list per input.
  Every `rp-address` line appends to `g_rp_hold`, which only
  `del_static_rp()` in `main.c` frees, and `config_vifs_from_file()`
  synthesizes one for each SSM range in effect, so every input added one
  whatever the file said: peak RSS grew 39MB over 600k inputs, and a long
  hunt ended at libFuzzer's own RSS limit reporting an out-of-memory where
  nothing had leaked
- `src/` builds everything but `main.c` into a static convenience library,
  `libpimd.a`, and `pimd` links that plus `main.c`.  The binary is the same;
  what this buys is a harness in another directory linking the daemon's own
  objects rather than a second copy of the source list
- `pimsend` takes `-x COUNT` to flip that many bytes of a message's body
  before sending it, `-S SEED` for what those flips are drawn from, and
  `-b FILE` to send the bytes of a file verbatim.  The checksum is computed
  after the flips, or every mutant would die at the checksum test that opens
  most `receive_pim_*()` and none would reach a parser; the first four bytes
  are left alone, version and type each having an option of their own.
  Under `-c COUNT` the flips are redrawn per packet, and a seed draws the
  same packets on FreeBSD as on Linux, so a flood that trips something is a
  flood somebody can send again
- New `fuzz` scenario in `test/lab.sh`: crafted's topology and sender, with
  messages that are wrong in no particular way instead of in one named way
  -- five hundred mutants of every type `pimsend` can build, at a pimd that
  has neighbours, an RP set, a kernel MFC and a register vif behind its
  parsers, which is what an in-process harness has none of.  Under
  `SANITIZE=yes` the sanitizers are the assertion; without them the scenario
  asserts that R1 stayed up, stayed the same process, kept its neighbours
  and its RP set, and still parsed a well-formed Join afterwards -- a daemon
  that any host on its LAN can silence being a bug of its own.  Which RP it
  holds afterwards is deliberately not asserted: a mutant Bootstrap that
  comes out valid is a BSR takeover by a sender that has said Hello, which
  is RFC 7761 sec. 4.7 working rather than pimd going wrong, and
  `accept-nbr-from` is the answer to it
- New interoperability lab, `test/frr-interop.sh`, pimd against FRRouting's
  own `pimd` on both supported systems.  It builds the chain of boxes
  `test/lab.sh` builds, through the same `lab-freebsd.sh` and
  `lab-linux.sh` backends, and runs FRR's `zebra` and `pimd` in the middle
  box: a second implementation on the wire, which is what tells a field
  pimd encodes wrongly from one both ends read the same wrong way, and
  unlike `test/freebsd-interop.sh` it costs a package rather than a
  licensed VM image.  Three scenarios, `frr-rp` and `pimd-rp` mirrors of
  each other so that each side writes what the other parses -- Bootstrap,
  Candidate-RP-Advertisement, `(*,G)` Join, Register and Register-Stop,
  each ending in traffic counted in replies -- and `autorp`, which is the
  only test of pimd's Auto-RP against a parser that is not pimd's, in both
  directions: pimd announcing to FRR's mapping agent, then FRR announcing
  to pimd's.  `-s SLOT` and `-j JOBS` work as they do in the other labs,
  each slot keeping its FRR state in a pathspace of its own; on Ubuntu the
  lab says so when AppArmor refuses that pathspace, and prints the override
  rather than applying it

### Fixes
- An Assert that names one source no longer takes the whole group off the
  interface.  RFC 7761 sec. 4.6.2 lets the (\*,G) Assert machine run only where
  the (S,G) one held no state and did not move, and `assert_machine()`
  (`src/pim_proto.c`) reported one case as "not mine" that was: the (S,G)
  machine that compared metrics, lost, and then could not create the (S,G)
  entry its Loser state has to live on -- no unicast route to S, no RP for the
  group, or an (S,G) refused by one of the limits.  `receive_pim_assert()` went
  on to the (\*,G) machine with it, which recorded that one source's loss as the
  group's and emptied the olist every other source of G inherits from it, for
  `Assert_Time`.  The shape it was found in: a renumbered interface leaves the
  route to a source on that segment unresolvable for a moment, so a DR that had
  just been renumbered stopped forwarding the stream it was forwarding over an
  Assert about a source it was not forwarding at all, while the router beside it
  carried the LAN instead -- a kernel MFC with no incoming vif and no outgoing
  interfaces, 90 seconds after the renumbering.  The machine says
  `ASSERT_REFUSED` now, which is the same answer as `ASSERT_MOVED` to the
  ordering of sec. 4.6.2 and differs only in having kept nothing.  Step 2c of the
  `crafted` scenario of `test/lab.sh` is the assertion, and it is deterministic
  where the bug was not: four messages from `test/pimsend.c`, a Join(\*,G) to
  forward a group of its own, an Assert carrying the RPT bit and a worse metric so
  that R1 holds the interface as the (\*,G) winner, then the one no pimd sends --
  an Assert with the bit clear, a better metric and a source R1 has no route to --
  which must leave that Winner state alone.  Two controls beside it, since a
  daemon that ignored every Assert would pass the assertion on its own: the same
  Assert for a source R1 can route, which is kept, and on an (S,G) of its own.  It
  was found instead in step 8 of `assert-recover`, which reproduces it about one
  run in five with eight scenarios in parallel -- and 0 in 8 with the fix -- the
  way `shared-lan-spt` reproduces the SPTbit deviation of
  `doc/rfc7761-compliance.md` only under `-j 4`
- A Leave that arrives while the interface it came in on is going away no longer
  leaves pimd writing into freed memory.  `accept_leave_message()`
  (`src/igmp_proto.c`) answers a Leave with a group specific query and then
  writes the group's three timers, and the send in between could take the group
  out from under it: a `sendto()` that failed with `ENETDOWN` or `ENODEV` called
  `check_vif_state()` from inside the send path, which takes the interface out of
  service with `stop_vif()`, which frees every membership of that VIF -- so the
  write landed in a freed `struct listaddr`.  Nothing about that is particular to
  IGMP or to memberships.  `stop_vif()` also frees the VIF's querier, its PIM
  neighbours and the routing entries that named it, and the callers a few frames
  above every one of those four sends are receive paths holding exactly such a
  pointer, so the shape was a class rather than one bug.  A failed send asks for
  an interface scan with `rescan_vifs_request()` now, the same coalescing request
  the kernel's own interface notifications take, and the scan runs from the timer
  where no parser's state is on the stack.  Nothing is noticed later than it was:
  `age_vifs()` calls `check_vif_state()` every `TIMER_INTERVAL` whatever a send
  did, and the comment there says why it cannot be left to the send paths.  Found
  by the `rpt` scenario of `test/lab.sh` under `SANITIZE=yes`, whose step 10
  destroys an interface pimd is forwarding out of while a host on it leaves a
  group, and found on the first run of it that could report at all -- the
  sanitizer entry above, the one about a report thrown away, is why
- A host on the link can no longer make pimd write a syslog line per packet.
  `dvmrp_accept_neighbors()` (`src/dvmrp_proto.c`) logged every DVMRP neighbour
  list it dropped at `LOG_INFO` and unconditionally, so one IGMP type 0x13 code 4
  per packet from anywhere on the segment was one line per packet; both its
  siblings were already behind `IF_DEBUG(DEBUG_PKT)`.  The two dispatch defaults
  of `accept_igmp()` (`src/igmp.c`), for a DVMRP code and an IGMP type nothing
  claims, were the same shape and are behind the flag too.  This is the policy the
  file already states where it drops a query of no version: anyone on the link can
  produce the line at will, and dropping the packet is the whole of what happens,
  so an operator who has not asked for packet debugging has nothing to do with it
- A group an IGMPv1 host reported ignores a Leave for as long as RFC 3376
  sec. 7.3.2 says, rather than for one query interval.  RFC 2236 gives a v1 host
  no way to send a Leave, so one for such a group cannot have come from every
  member and must be ignored while a v1 host is present -- and pimd kept a memory
  of its own for that beside the group's compatibility mode: `al_old`, set to 2 by
  `DVMRP_OLD_AGE_THRESHOLD` and aged by `TIMER_INTERVAL`, 5, in `query_groups()`.
  The first ageing pass therefore zeroed it whatever the constant meant to say,
  and the comment on it said "# of query intervals" while the arithmetic said
  seconds, so a v1 host was forgotten after one query interval -- 125s against the
  385s the RFC asks for with pimd's own constants -- and a Leave arriving in
  between tore down a group a v1 host was still a member of.  The test that
  reproduces it is asked of the mode the daemon already keeps correctly, `al_pv`
  and its per-version Older Version Host Present timer, and `al_old` and the
  constant are gone.  Step 6 of the `igmp-compat` scenario is the regression test:
  a Leave sent two query intervals in has to leave the membership standing, and
  the same Leave once the interval has run out has to take it away
- A cache miss for traffic that arrives on an interface this router forwards the
  group out of sends the Assert that RFC 7761 sec. 4.6.1 asks for.  Its NoInfo
  state answers "data arrives from S to G on I and CouldAssert(S,G,I)" by sending
  one, and `process_cache_miss()` (`src/route.c`) did not: only
  `process_wrong_iif()` did, and the kernel raises that upcall only once it has an
  entry for the flow, so the Assert waited for a packet that follows one the
  kernel had no entry for.  Both now use the same call and the same reading of
  CouldAssert(S,G,I), an interface found in the entry's oif list, which
  `calc_oifs()` never leaves the incoming interface in.  The window it closes is
  narrow -- a router with an oif for the group has joined towards the source, so
  it usually also receives the traffic on its own incoming interface, installs an
  entry, and reaches the Assert through the wrong-iif upcall on the next packet --
  and there is no test: which of the two copies arrives first is a race, so
  nothing can hold the daemon to the earlier one
- An interface that goes out of service leaves the routing table as well as the
  kernel.  `delete_vif_from_mrt()` (`src/route.c`) was a stub that returned TRUE,
  and neither `route.c` nor `mrt.c` tests `VIFF_DOWN` anywhere, so a stopped VIF
  stayed in every interface set of every entry after `stop_vif()` had deleted its
  kernel vif: `calc_oifs()` went on offering the slot, which kept
  `join_desired()` true for a group whose only outgoing interface had gone, so
  the router asked its upstream for traffic it could no longer deliver -- and the
  bits were still set for whatever interface took the slot next.  It now clears
  the interface from all nine of an entry's interface sets, zeroes its slot in
  the four per-interface timer arrays, and drops the Assert election held on it
  (`assert_vif_gone()`, `src/pim_proto.c`, which unlike `assert_clear()` does not
  spare a link this router won, an interface the kernel no longer has owing
  nothing to anybody), then recomputes the outgoing list.  The incoming interface
  is deliberately left to `age_routes()`, which re-runs `set_incoming()` per
  source and deletes what has become unroutable.  Step 9 of the default scenario
  in `test/lab.sh` is the regression test
- A membership pimd is already holding is offered to PIM again when an adjacency
  comes up, and an SSM group is offered one per source.  `find_route()` cannot
  build an entry for a source whose RPF neighbour is not a PIM neighbour yet --
  `create_srcentry()` gives up on that -- so a report that arrived before the
  first Hello from the router towards the source was recorded as a membership
  with no routing entry and no outgoing interface behind it.  Nothing then came
  back to it: `resync_leaves()` was called only when a group range gained an RP,
  and it skipped the SSM range by name, so the repair was the host reporting
  again, up to a query interval later.  It now walks the sources of an SSM group,
  and `receive_pim_hello()` calls it for a neighbour that is new or has rebooted,
  which is half of the answer to the question left open at the end of that
  function.  Step 8 of the `ssm` scenario in `test/lab.sh` is the regression
  test, and the same gap for an any-source membership is covered by the same two
  callers
- A membership for one SSM source no longer decides what the router forwards for
  the others.  `add_leaf()` and `delete_leaf()` (`src/route.c`) finished by
  walking every (S,G) of the group and setting or clearing the receiving
  interface in all of them.  That is right for an any-source membership, which
  is (\*,G) state every source of the group inherits, and wrong inside the SSM
  range, where the membership names one source: RFC 7761 sec. 4.1.6 builds
  `pim_include(S,G)` from `local_receiver_include(S,G,I)`, "local members on
  interface I desire to receive traffic sent specifically by S".  So a join for
  one source put every other source of the group onto that link, with a kernel
  MFC entry each, and traffic nobody asked for was delivered until a leave; and
  a leave for one source took the link away from the others, whose members were
  still there and still asking, with nothing to restore it before their next
  report -- `resync_leaves()` skips the SSM range.  Reasoned from the code and
  the RFC rather than reproduced: `doc/TODO.org` records what stopped a lab
  scenario from telling the fix from the bug, which is that an SSM membership
  can be taken and leave no forwarding state behind at all
- A neighbour that goes away no longer leaves a freed pointer in the RP entry
  that was reaching the RP through it.  `set_incoming()` (`src/route.c`) has four
  returns and three of them clear `upstream`; the fourth, taken when the kernel
  has no route to the address at all, kept whatever was there.  `delete_pim_nbr()`
  (`src/pim_proto.c`) calls it to replace a neighbour it is about to free, and its
  RP loop keeps the `rpentry_t` deliberately -- remapping every group of an RP
  because the route to it went away would tear down the shared trees that a
  Bootstrap is about to repair -- so what it kept was a pointer to freed memory.
  `find_route()` (`src/mrt.c`) then copies it into each new (\*,G) of that RP, and
  `add_jp_entry()` dereferences it on its first line.  Losing the neighbour is usually what removed
  the route, so this was the common case: destroying a router's upstream interface
  and reporting one group behind it is enough, and AddressSanitizer answers
  `heap-use-after-free` in `add_jp_entry()` freed by `stop_vif()`.  Same shape as
  the `mrtentry_t` half fixed for troglobit/pimd#22, one struct up.  The
  `rp-nbr-gone` scenario of `test/lab.sh` is the regression test, and it needs
  `SANITIZE=yes`: against the unfixed daemon a plain build passes it
- The directory the unprivileged half is confined to is checked and used as one
  open descriptor.  `priv_do_chroot()` (`src/privsep.c`) resolved
  `PRIVSEP_CHROOT` twice, once for the `stat()` that has to find a directory
  owned by root and writable by nobody else and once for the `chdir()` that
  trusts what it found, so anything able to replace that path between the two
  chose where the half of the daemon that parses the wire lives -- which is the
  one thing the check exists to prevent.  It opens the directory once with
  `O_DIRECTORY` now, tests it with `fstat()` and moves into it with `fchdir()`,
  so there is no second lookup to race, and the descriptor is closed rather
  than left as a way back out of the new root.  Reaching it wanted write access
  to the parent directory, so root already; found by Coverity, CID 1680252
- An administrative boundary, `phyint ... scoped`, is the edge of the zone in
  both directions: a packet of a scoped group that arrives on a boundary
  interface has crossed it already, so it is forwarded nowhere at all rather
  than out of every interface except that one.  pimd consulted a boundary only
  when it chose outgoing interfaces, so a group scoped on a router's upstream
  link was carried into the zone and delivered to every member inside it, which
  is the direction a boundary on the receiver's own link cannot show.  That is
  how the keyword's model elsewhere behaves, one boundary filtering a group in
  and out, and `man/pimd.conf.5` says so.  Step 6b of the `altnet` scenario is
  the regression test
- An administrative boundary, `phyint ... scoped`, applies to the interface it
  is configured on and no longer to every interface of the router.
  `APPLY_SCOPE()` (`src/route.c`) cleared an entry's whole outgoing interface
  list as soon as any vif of the router was a boundary for the group, so one
  boundary stopped that group being forwarded out of every other link as well:
  a router with a member behind a boundary and a member on an ordinary link
  served neither, and a boundary on a router's upstream link -- an incoming
  interface, and nothing's outgoing one -- stopped the group reaching anybody
  at all.  `man/pimd.conf.5` says which interface the boundary belongs to now.
  Step 6d of the new `altnet` scenario is the regression test, and it needs the
  second receiver LAN that scenario grew for it: on a chain a last hop router
  has one interface a member can sit behind, so "take that interface out of the
  list" and "forward nothing at all" are the same observation, which is how this
  survived.  With members on two LANs behind R3 and a boundary on one of them,
  the unscoped LAN is served and the scoped one is not; under the old reading
  both went, which is what the step reports (2 assertions, measured)
- And it survives the state changing under it.  A boundary was applied by a
  macro at two of the seven places that install a kernel MFC entry, so an entry
  any of the other five reinstalled went in with the boundary interface
  forwarding again: `change_interfaces()` (`src/route.c`) recomputes an
  outgoing interface list and installs it, which is what a membership going
  away and coming back makes it do, and a scoped group was then forwarded out
  of the boundary for as long as that entry lived.  The boundary is asked for
  in `k_chg_mfc()` (`src/kern.c`) now, the one place such a list reaches the
  kernel, so it holds however the entry was installed; the entry's own list is
  left alone, so `pimctl show mrt` still names the interface, the boundary
  being a filter on the packets rather than a prune of the tree.  Step 6c of
  the `altnet` scenario is the regression test, and it needs a membership that
  can be withdrawn -- a v2 report from `test/igmpv3` and a v2 leave, since a
  receiver that joined with a socket answers every group-specific query and
  never leaves, which is why a first attempt with `mping` saw nothing.  One of
  the two places that used to apply it had a second bug of its own, scoping one
  entry and installing another one's list, under a comment wondering whether
  scoped traffic reached it at all; both are gone with the macro
- One group range takes at most 255 RPs, which is what a Bootstrap can say it
  holds: the count is a byte on the wire (RFC 5059 sec. 4.1) and a byte in
  `grp_mask_t`, and each Candidate-RP Advertisement names one RP, so 256
  messages wrapped it to zero -- a false count on the wire, and a length that
  disagreed with the list the message was built from.  The 256th RP for a range
  is refused now and the fact logged once
- A Bootstrap says what it holds: the RP count of each group set is counted from
  the list the message is written out of rather than taken from that byte, and
  exactly that many records follow it
- `rp-set-limit` counts the RP set, not the half-sets waiting to be assembled.
  A Bootstrap whose group set is fragmented (RFC 5059 sec. 4.1) is held in a
  list of its own until the rest arrives, and that list is freed wholesale, so
  counting it made the total climb by a range per fragmented Bootstrap until
  every new range was refused.  pimd sends no fragmented Bootstrap itself, so
  this needed a BSR that does
- A bootstrap router no longer writes its RP set past the end of the send
  buffer.  `create_pim_bootstrap_message()` (`src/rp.c`) walked every group
  range of the set and every RP under it into a 128K buffer with nothing
  bounding the walk -- "TODO: XXX: No fragmentation support (yet)" -- and the
  set is not this router's to size: a Candidate-RP Advertisement is unicast
  to the elected BSR, so `receive_pim_cand_rp_adv()` asks for no neighbour
  relationship and no place on any of its links, and one message names up to
  255 group ranges.  Forty of them from a host that had sent no Hello, 10200
  ranges, walked the buffer off its end on the next Bootstrap:
  AddressSanitizer, "heap-buffer-overflow ... 0 bytes after 131072-byte
  region", in a lab of three routers.  The message is bounded now, and an RP
  set that does not fit is cut short and said once rather than written out;
  `rp-set-limit` below bounds the set itself
- The IGMPv1 *interface* mode is gone, with the seven branches that served
  it.  `VIFF_IGMPV1` could not be set: the `phyint` parser took `igmpv2` and
  `igmpv3` only and cleared the flag in both cases, so nothing in any
  configuration ever reached the code that sent a Max Response Time of zero,
  refused a v2 query, or asked a group at v1 because of the interface.  IGMPv1
  *hosts* are unaffected and still supported, which is the part RFC 3376
  sec. 7.3.2 asks for: a v1 membership report still puts its own group into v1
  compatibility mode, that group is still asked with a v1 group-specific query
  and still ignores leaves while the old host is there, and `pimctl show igmp
  groups` reports it.  What went is a mode nobody could turn on for hosts that
  no longer exist
- A group stops being treated as an older version's when the older hosts go
  quiet, however old they were.  `switch_version()` moved a group up one
  version per timeout and armed no timer for the next one, so a group a v1
  host had reported climbed to v2 and stayed there for as long as the
  membership lasted; each version gets a timeout of its own now, which is
  what RFC 3376 sec. 7.3.2 asks for
- A v1 group-specific query is no longer logged as a v2 one.  The query is
  named by the length of the message in the log, and a v1 query is eight bytes
  like a v2 one
- A separated pimd no longer dies, silently and with an empty log, when its
  unprivileged half has more to say than the privileged one can write down.
  The two halves talk over a unix `SOCK_SEQPACKET` socketpair, which on
  FreeBSD carries no `PR_ATOMIC` and runs through `sosend_generic()` like a
  stream: a blocking `sendmsg()` that has copied part of a message and is
  waiting for room returns *what it copied* when a signal arrives, not
  `EINTR`, and pimd takes a signal every `TIMER_INTERVAL` with no
  `SA_RESTART` anywhere.  `msg_send()` read that short count as "the peer is
  gone" and left the fragment in the socket, so the far half then read its
  next message across it: either a message that came up short, which the
  parent also read as the child being gone, or a shifted one, logged as
  "Privsep helper asked for operation 0, which does not exist".  Either way
  the parent unlinked the pimctl socket and exited without a word, and the
  child went with it -- the log it tried to write being the thing that broke.
  Both sides resume a short transfer from where it stopped now, and
  `SIGPIPE` is ignored so that a half whose peer really is gone says so
  instead of being killed by the default action, which leaves nothing in the
  log and nothing in `dmesg` either.  Seen twice on the FreeBSD CI runner as
  the `anycast` scenario losing its RP mid-burst, and reproduced on demand by
  stopping the privileged half, flooding the unprivileged one with work that
  makes it log, and signalling it while it blocks
- A `pimctl` reply longer than the socket buffer is no longer cut off.  The
  client socket is a non-blocking stream, so a write takes what fits and says
  how much that was; `ipc_write()` read anything short of the whole as the
  client having gone, dropped the rest and reported failure, which `show mrt`
  on a router with enough state was the command to notice.  It sends the
  remainder now.  The reply that says a tempfile could not be created went
  through `write()` directly with the length `snprintf()` *wanted* rather than
  the one it wrote, which was past the end of the buffer whenever that message
  was truncated; it goes through `ipc_write()` like every other reply.  Both
  were found by the Coccinelle rule that came out of the privsep fix above
- `pimctl debug SYSTEM` says which subsystems are on rather than always
  answering `all`, and so does the `debug level 0x... (...)` line a daemon
  started with `-d` prints.  `debug_list()` took the first row of
  `debugnames[]` whose level shared a bit with the mask, and the first row
  is `all`, which carries every bit there is: `pimctl debug pim_jp` replied
  `all`, and so did `debug` with anything at all enabled.  A row answers now
  only when every bit it names is on, and the rows that stand for several
  subsystems are tried first, so `debug pim` is answered by `pim` rather
  than by the nine names underneath it.  `pimctl debug ?` and the
  `Available subsystems` list of `--help`, which are the same function asked
  with `DEBUG_ALL`, are unchanged.  Found while writing `fuzz_ipc`, whose
  corpus asks both questions
- The "this RP is static" sentinel is spelled `PIM_HELLO_HOLDTIME_FOREVER`
  in all four places now.  `src/main.c` stored it as `(uint16_t)0xffffff`
  and `src/pim_proto.c` compared against the same, one `f` too many, which
  the cast quietly turned back into the `0xffff` that `src/pimd.h` defines
  and that `src/ipc.c` and `src/debug.c` test for.  Right by truncation, on
  both sides, so nothing misbehaved -- and a trap for whoever widens
  `adv_holdtime`, since the two literals would then stop agreeing with the
  two macros.  No change in behaviour.  Found by `sparse` (`cast truncates
  bits from constant value`), which is the only checker run over this tree
  that had anything to say about it
- `pimctl` no longer decides what went wrong from an `errno` that
  `close(3)` or `warn(3)` may have overwritten.  `try_connect()` read it
  after closing the socket, and its callers read it after it returns:
  `ipc_connect()` retries with a `.sock` suffix on `ENOENT` and gives up on
  `EACCES`, and `cmd()` turns it into the message the user sees, so a
  clobbered value is "no pimd running" for a socket that is there, or the
  reverse.  The connect(2) failure is saved and put back on every way out
  of that function now, which is the contract the callers were already
  assuming.  Found by `scan-build` (`unix.Errno`), which had four more of
  these to say once the first was out of the way
- `accept_group_report()` no longer leaks the group it just allocated when
  the source allocation behind it fails.  In the SSM path the new
  `struct listaddr` for the group is not on `uv_groups` yet, so the early
  return on the second `calloc()` was the one way out of that function that
  had to give it back.  Invisible in an ordinary build, where
  `logit(LOG_ERR)` calls `exit()` and the question never arises -- and live
  in a tree configured `--disable-exit-on-error`, which is what the fuzz
  harnesses and the OSS-Fuzz build are.  Found by `gcc -fanalyzer`
  (`-Wanalyzer-malloc-leak`), the one thing it had to say about the whole
  tree
- A `masklen` that cannot be read is reported and defaulted again.  Three
  keyword parsers in `src/config.c` tested `if (!sscanf(...))`, and
  `sscanf()` answers `EOF`, not zero, when there is nothing to convert --
  `group-prefix 224.0.0.0/` with the length left off, or `masklen` as the
  last word on the line -- so the test was false on exactly the input it
  was there to catch.  In `parse_prefix_len()` that skipped the warning and
  the default both, and the caller's length kept whatever it had; the other
  two sites default at their declaration and so came out right by luck.
  Every other `sscanf()` in the file already read `!= 1`.  Found by CodeQL
  (`cpp/incorrectly-checked-scanf`), and reproduced: `group-prefix
  224.0.0.0/` now logs "Invalid masklen ''" where it logged nothing
- The PID file is created 0644 rather than 0666 masked by whatever `umask`
  pimd inherited -- world-writable when that is empty, and the file a
  SIGHUP is sent by the contents of.  `lib/pidfile.c` used `fopen(path,
  "w")`; it opens with an explicit mode now, which is the argument
  `src/ipc.c` already makes for the control socket.  An existing file keeps
  the mode it has.  This is the fallback `pidfile()` -- glibc has none, so
  Linux builds it.  Found by CodeQL (`cpp/world-writable-file-creation`)
- `configure` no longer drops every hardening flag when the user's own
  `CFLAGS` carry warning options.  The compiler probe adds `-Werror`, so a
  `-W` flag of the user's that fires on the probe's own test program failed
  all of them and left `PIMD_CFLAGS` empty without a word; the linker
  probes have no `-Werror`, kept their half, and the build then linked
  `-pie` objects compiled without `-fPIE`: "relocation R_X86_64_32 cannot
  be used against local symbol".  The probe strips the user's warning flags
  now, and `-pie` is asked for only when `-fPIE` was taken
- `mping` no longer writes past the end of the buffer it is given.  Its
  `strlencpy()` placed the terminating NUL one byte past the end whenever
  the source filled the destination, two call sites then wrote a second one
  at the same place, and the `/proc/net/route` scan read a 16 character
  interface name with `%16s` into a `char[16]`, which is 17 bytes with its
  NUL.  Found by gcc's `-Warray-bounds` once the file's globals were
  `static` enough for it to see the sizes
- `mping` no longer skips every interface when no address family is given.
  The `continue` in the `AF_UNSPEC` arm of `ifinfo()` was indented as if
  the `if` above it guarded it, but that `if` had no braces, so the arm
  skipped the interface whatever its address family was.  Latent rather
  than live: the only caller asks for `AF_INET`.  Found by
  `-Wmisleading-indentation`, which arrived with the flag probe above
- The `lib/` compat declarations are guarded by the `HAVE_*` macros
  `configure` actually defines.  `src/defs.h` and `src/pimctl.c` guarded
  them with `#ifndef strlcpy` and friends -- a test for a *macro* of that
  name, which libc never defines -- so the declarations were unconditional
  and collided with the system headers' own.  `src/pimctl.c` also tested
  `strlcat` twice, once while declaring `strlcpy`.  Harmless until
  `-Wredundant-decls`, which is how they surfaced
- A multicast traceroute request is measured against the send buffer before
  it is copied into it, rather than after.  `accept_mtrace()` copied the
  whole request into `igmp_send_buf` and only then asked whether there was
  room, a test written for a different question: whether this router's own
  response record still fits behind the copy, which is what relays a
  `TR_NO_SPACE` inside it.  Nothing overflowed -- the request arrives on a
  raw IP socket, so its length is bounded by the sender's IP total length
  field at about 64 KiB, well under the 128 KiB buffer -- but the copy was
  the one place in the daemon whose bound came from somewhere other than
  the code above it.  An oversized request is now dropped with a warning.
  Found with `rules/security.cocci`
- An interface that has gone no longer holds on to its subnet.  The vif of
  a removed interface keeps its slot, its address and its subnet, so that
  the same name comes back to the same vif rather than to a new one; the
  interface scan took that stale subnet for a claim, and refused a vif to
  any other interface carrying it: `Ignoring em2, same subnet as em1`,
  naming an interface the kernel no longer has, with only a restart to
  clear it.  That is an address failing over to another NIC, or a VLAN
  rebuilt under another name.  The scan now asks whether the kernel still
  has an address on the interface, rather than what the vif flags say, so
  an interface that is merely down keeps its subnet as before.  Tested by
  the `ifgone` scenario of `test/lab.sh`


- `logit()` no longer trips `-Wc23-extensions` in a tree configured
  `--disable-exit-on-error`: with `CONTINUE_ON_ERROR` defined the `done:`
  label had no statement after it, which is a C23 extension in C17 and an
  error under `--enable-werror`

[v3.1.0][] - 2026-09-18
-----------------------

### Changes
- Interfaces are rescanned while pimd runs, so one configured after the
  daemon started becomes a vif of its own.  The kernel interface list used
  to be read once, by `init_vifs()`, and the periodic poll only flipped the
  vifs built from that one reading between up and down: an interface that
  appeared later never became a vif, and only a restart could give the
  daemon a correct table.  That is the ordinary case wherever links are
  negotiated rather than configured -- PPP, L2TP, a tunnel that comes up, a
  VLAN added to a router in service, and any of them beside a pimd started
  from an rc script.  A second routing socket (`PF_ROUTE` on BSD,
  `NETLINK_ROUTE` subscribed to the link and IPv4 address groups on Linux)
  is read from the event loop, and an interface or address message asks for
  a scan a second later; a scan every minute is the floor under that, for a
  notification the kernel had to drop.  The `phyint` lines of `pimd.conf`
  are applied to the vifs that appear, including the ones naming an
  interface that did not exist when the file was read.  An interface that
  comes back under a name pimd already has a vif for keeps that vif, on the
  address and ifindex it has now, so a link that comes and goes costs one
  vif and not one per flap.  Tested by the `ifnew` scenario of `test/lab.sh`

### Fixes
- Daemonizing leaves the terminal that started pimd.  The BSD branch asked
  for `TIOCNOTTY`, an ioctl the kernel refuses to anyone but a session
  leader -- which the child of a `fork()` never is -- and pimd threw the
  error away, so it kept the controlling terminal and stayed in the process
  group of whoever started it.  Started from an rc script on a console, it
  died on the next INTR character typed there.  The Linux branch called
  `setpgrp()`, which leaves the session and the terminal attached.  Both are
  replaced by `setsid()`, which is what either meant, and a `fork()` that
  fails is now reported rather than ignored
- `redhat/pimd.spec` builds again, and packages the whole daemon.  It was
  written for a branch export of a 2.x tree: it named a version that was
  never released here, unpacked `pimd-master`, and looked for the binary
  and the manual page at the top of the tree, where GNU Configure and
  Build has not put them since.  `pimctl`, `pimctl(8)` and `pimd.conf(5)`
  are in the package now, and RFC 7761 is the specification the
  description names.  It still ships a SysV init script rather than the
  `pimd.service` this tree has
- Five checks that were not where the value they guard is used, from a
  pass over a Coverity report.  None is reachable and none changes what
  pimd does: the `inet_cksum()` accumulator was a signed `int`, which the
  most a full IP datagram can put in it clears by 32767 and a larger
  buffer would not; `logit()` dereferenced `localtime()` without testing
  it, and now prints the message without its timestamp rather than losing
  it; `chomp()` in `src/ipc.c` walked off the front of its buffer for a
  string of nothing but newlines, the bound its twin in `pimctl.c` already
  carried; `lost_assert()` took a pointer whose NULL test lived in another
  function; and `k_req_incoming()` read the header of a netlink reply
  before knowing the reply was that long


[v3.0.0][] - 2026-09-18
-----------------------

As of this release pimd is not guaranteed to be backwards compatible
with earlier releases.  It is recommended to run the same version of
pimd on all routers in the same domain.  See issue #93 for details.

**Note:** command line arguments in v3.0 are not compatible with v2.x!

### Changes
- New `anycast-rp` setting in `pimd.conf`: Anycast-RP using PIM, RFC 4610.
  Several RPs hold one RP address, usually on a loopback, and unicast
  routing takes each DR's Registers to the nearest of them; each line names
  one member of the set by its unique address.  A member copies every
  Register it gets from outside the set to the other members, so that a
  receiver joined at any member reaches every source with no MSDP between
  them, and a member that is itself the DR of a source registers it to the
  others.  A member that is sent a copy creates the (S,G) state whether or
  not it has receivers, and one that has receivers joins the source tree.
  `pimctl show status` lists the sets and counts the copies sent.  Where
  this differs from the RFC: on FreeBSD a copy of a data Register is a
  Null-Register, the kernel handing pimd only the headers; a copy's TTL is
  one less than the Register's; and the join on a copy ignores
  `spt-threshold`.  A member copies at most 256 Registers a second, and at
  most 64 of them whole, the rest as Null-Registers, since the sender need
  not be a DR that rate-limits itself.  See pimd.conf(5).  Tested by
  the
  `anycast` and `anycast-dr` scenarios of `test/lab.sh`, and in both
  directions against an Arista vEOS 4.36.1F member by the `anycast` scenario
  of `test/freebsd-interop.sh`
- New `accept-nbr-from` setting for a `phyint` in `pimd.conf`, the routers
  an interface accepts PIM messages from.  RFC 7761 sec. 6.2 asks for the
  option and requires it to default to accepting every router, which an
  interface with no `accept-nbr-from` does, so nothing changes until it is
  used.  Without it every router that sends a syntactically valid Hello on
  a subnet pimd has an interface on becomes a neighbour of it, and from
  there can take the DR role, take part in the assert election and have its
  Joins believed.  Repeatable on one line, and with no prefix length the
  address is one router.  Refusing a Hello is what does the work: a
  Join/Prune, an Assert and a unicast Bootstrap are all refused from a
  router no Hello has been accepted from.  It is worth as much as the
  addresses on the link are -- sec. 6.3's IPsec is the other half, and pimd
  neither installs nor requires a security association
- New `register-accept-from` setting in `pimd.conf`, the routers an RP
  accepts PIM Register messages from.  RFC 7761 sec. 6.2 asks for it and
  requires it to default to accepting every sender, which is what a
  configuration without the setting does, so nothing changes until it is
  used.  Without it any host able to unicast to an RP can have traffic of
  its choosing decapsulated onto a shared tree, which is the attack
  sec. 6.1.2 describes.  It matches the sender of the Register, the DR,
  rather than the source address of the encapsulated packet, which is a
  different control.  Note that it refuses the routing state, the
  keepalive and the Register-Stop, and not the encapsulated packet
  itself: decapsulating is the kernel's work and happens before pimd is
  handed the message, so an RP that must keep forged traffic off a shared
  tree needs a packet filter for IP protocol 103 as well
- New `rpt-prune-limit` setting in `pimd.conf`, default 1024: how many
  (S,G) entries the Prune(S,G,rpt) messages of PIM neighbors may make pimd
  hold.  Each one names a source of the sender's choosing and lasts as long
  as its HoldTime asks, up to 18 hours, so one neighbor could otherwise
  grow the routing table, and the lists every Join/Prune is looked up in,
  without bound.  Past the limit a Prune addressed to pimd is not applied,
  and one overheard upstream is overridden with an early Join(*,G) instead
  of a Join(S,G,rpt).  `pimctl show status` reports the count
- New `register-sg-limit` setting in `pimd.conf`, default 4096: how many
  (S,G) entries PIM Register messages may make pimd hold as an RP.  A
  Register names a source and group of the sender's choosing and is
  unicast from anywhere, so one sender could grow the routing table on an
  RP without bound, and with `anycast-rp` a Register claiming a member's
  address also makes the member join the source tree.  Past the limit a
  Register still gets its Register-Stop but makes no state.  `pimctl show
  status` reports the count.  RFC 7761 sec. 6.4, RFC 4610 sec. 6.1
- New `local-sg-limit` setting in `pimd.conf`, default 4096: how many
  (S,G) entries data from directly connected sources may make pimd hold as
  their DR.  Every packet to a group with no entry yet made one, with a
  kernel cache entry beside it, and on its own subnet the sender picks
  both the group and the source, so one host could otherwise grow the
  routing table until an allocation failed and pimd exited.  Past the
  limit a new source is not registered, and so not forwarded beyond its
  LAN; entries already held are unaffected.  `pimctl show status` reports
  the count.  RFC 7761 sec. 6.4
- Remove RSRR, Routing Support for Resource Reservation, the RSVP
  interface built with `--enable-rsrr`.  It implemented
  draft-ietf-rsvp-routing-02, an Internet-Draft that expired without
  becoming an RFC, was disabled by default, was never covered by a test,
  and its own TODO entry recorded that it had never been tested.  The
  `--enable-rsrr` configure flag and the `rsrr` debug level of `-d` are
  gone with it
- Remove the (*,*,RP) and PIM Multicast Border Router (PMBR) features.
  RFC 7761, which obsoletes RFC 4601 and is the current PIM-SM standard,
  removed both in its Appendix A for lack of implementation and
  deployment experience.  In pimd they were reachable only from a peer's
  Join(224.0.0.0/4): nothing else ever created a (*,*,RP) entry, and the
  code that originated one was itself gated on already having one, so in
  any RFC 7761 domain none of it could run.  pimd still parses and skips
  a (*,*,RP) group entry in a received Join/Prune, it just no longer
  builds state from it.  The third feature RFC 7761 removes,
  authentication using IPsec, was never implemented here
- Converted to GNU Configure & Build system
- Replace libite (`-lite`) GIT submodule with compatibility functions.
  I.e., as of this release `pimd` is self-hosting again.
- PID file is touched to acknowledge `SIGHUP`
- Completely changed command line arguments, in part to alert users that
  this release may not be compatible with their existing PIM routers
- New pimctl(8) tool completely replaces `pimd -r` and SIGUSR1 support,
  pimd no longer dumps internal state in a pimd.dump file
- Add `-i IDENT` to change name of `pimd` in syslog, `.conf` file, and
  PID file. Useful when running multiple daemons, one per multicast
  routing table
- Converted to use `getifaddrs()` when scanning for interfaces. This is
  required on at least FreeBSD 9, since `SIOCGIFCONF` seems to be really
  broken there, at least on systems with lots of interfaces
  (>30). Problem repored by Vladimir Shunkov
- Issue #41: Added systemd unit file
- Issue #56: Support for `disable-vifs` in `pimd.conf`
- Issue #62: Modify Join/Prune send logic to allow more than ~75
  mcast receivers, by Joonas Ruohonen
- Issue #67: Stream optimization, by Mika Joutsenvirta:
  - Switch directly to shortest path only in the case of PIM-SSM
  - For new IGMP group reports, send PIM Join immediately, saves 0-5 sec
  - Forward PIM Join messages immediately.  One part of this was undone
    again, see the Fixes below: a new (\*,G) Join no longer builds
    forwarding state for every source of the group
- Issue #89: Allow use of loopback interface as long as MULTICAST
  flag is set, by Vincent Bernat
- Revert changes made for issue #66 and #73, no more implicit behavior
  of `bsr-candidate` and `rp-candidate`.  The case of no .conf file
  or commented out settings for the same, are now similar.  The default
  is now _disabled_
- Draw every random value from `arc4random()`, on all platforms.  pimd
  jitters its protocol timers, picks PIM Hello GenIDs and tags BSR
  bootstrap fragments with `RANDOM()`, which resolved to `arc4random()`
  only on the BSDs and to `random()` or `lrand48()` everywhere else.
  Those two are seeded predictably and their state can be recovered from
  the output, so a neighbor on the LAN could anticipate values it is only
  supposed to observe.  None of them are keys, but none of them are
  meant to be guessable either.  `configure` now looks for `arc4random()`
  and falls back on `lib/arc4random.c`, which reads the kernel generator
  through `getentropy()` or `/dev/urandom`, since GLIBC only grew an
  `arc4random()` in 2.36 and musl in 1.2.3
- Issue #185: New `ssm-range` setting in `pimd.conf` for the group range
  pimd treats as Source Specific Multicast, which used to be 232.0.0.0/8
  and nothing else.  Ranges given replace that default rather than adding
  to it, the way Cisco's `ip pim ssm range` does, so an `ssm-range
  default` line is what keeps 232.0.0.0/8 in service alongside a range of
  your own.  `pimctl show status` lists the ranges in effect.  Meant for
  interop with routers whose SSM range is already configured elsewhere,
  and for legacy deployments that never moved to 232/8
- New `pimctl show mfc` command, showing the multicast forwarding cache
  pimd has installed in the kernel: one line per (S,G), with the incoming
  interface, the outgoing interface list and the kernel's packet, byte
  and wrong-interface counters for that flow.  `show mrt` shows what the
  daemon believes, this shows what the kernel forwards, which until now
  meant reaching for `ip mroute show` or `netstat -g` on the side, and
  neither of those reports the wrong-interface counter
- New `pimctl show summary` command, one line per interface with the PIM
  and the IGMP view side by side: state, address, neighbor count, elected
  DR, IGMP version, elected querier and number of groups.  Users tend not
  to care which protocol answers for what, and until now that meant
  reading `show interface` and `show igmp interface` next to each other
- `pimctl show igmp groups` and `pimctl show igmp interface` are commands
  of their own now, instead of only being reachable together as `show
  igmp`.  Both were implemented but commented out of the command table
- `pimctl` accepts a few spellings people type anyway, as hidden aliases:
  `show if` and `show interfaces` for `show interface`, `show routes` for
  `show mrt`, and `show groups` for `show igmp groups`.  The prefix
  matcher could not help with these, `show if` compares against `show
  igmp` as "if" vs "ig" and against `show interface` as "if" vs "in", and
  matches neither
- Every address on an interface is now kept, not just the first one.  A
  second address is added as an `altnet` of the VIF the first one made,
  so a source or a neighbor on it counts as directly connected without
  anyone having to write the subnet out in `pimd.conf`.  Until now
  `config_vifs_from_kernel()` dropped it with an "alias for vif#N?" at
  debug level.  Ported from mrouted, commit `48a7a11`
- New `--enable-netlink` configure flag, which makes the RPF lookups go
  over `netlink(4)` instead of the routing socket.  FreeBSD has had
  netlink since 13.2, and answers the same `RTM_GETROUTE` there with the
  same attributes, down to mapping `RTA_PRIORITY` onto the
  `rt_metrics.rmx_metric` the routing socket reply carries, so `netlink.c`
  needed one `#include` to build on it.  The routing socket stays the
  default on BSD: it needs no kernel module.  Linux is unaffected, netlink
  is the only interface it has and the flag is implied there.  `pimctl
  show status` now reports which of the two a daemon was built with, as
  nothing else about a running router does
- `test/freebsd-lab.sh` is now `test/lab.sh`, and runs its scenarios on
  Linux as well, as root, over named network namespaces, veth pairs and
  Linux bridges instead of vnet jails, epairs and `if_bridge`.  What it
  needs of the host is in `test/lab-freebsd.sh` and `test/lab-linux.sh`,
  one set of functions per system, picked by `uname -s`
- The Linux-only scripts `make check` used to run are gone, every one of
  them a scenario of `test/lab.sh` now: it asserts what they did and more,
  reads pimd and the kernel back rather than only the traffic, and runs on
  FreeBSD as well as Linux.  The last three went once the lab grew what
  their shape needed -- a `solo` scenario, one router being DR, BSR, RP and
  last hop router at once, and two steps of `rpt`, which now contests both
  elections (the BSR going to R1 on the higher priority, the RP to R2 on
  the lower number, so a Cand-RP-Adv travels to a BSR elsewhere) and joins
  a group after its stream has started, the ordering of issue #192.
  `TESTS` is therefore empty and `make check` runs no test; the lab wants
  real root and named namespaces, which automake's unprivileged
  `unshare -mrun` cannot give it, so CI runs it as a job of its own on both
  systems.  `bird` and `tshark` are no longer needed by anything: the
  unicast routes were static in the lab all along -- pimd reads the FIB and
  never asks what wrote a route, there being no `RTPROT_*` in `src/` -- and
  the lab reads packets with `tcpdump`
- `test/lab.sh -j` and `test/freebsd-interop.sh -j` run from a directory
  that is not on `PATH` again: a slot is started by running the script
  again, and it was run as `$0`, which `sh lab.sh` leaves without a slash
  for the shell to look for in `PATH` and not find
- `test/lab.sh` takes `SANITIZE=yes` to run its scenarios against a pimd
  built `-fsanitize=address,undefined`, failing any scenario whose daemons
  reported anything -- which is not the same question as whether its
  assertions passed, and is how the two fixes above were found.  It asks
  the binary whether it holds a sanitizer runtime rather than trust the
  tree, and gives each daemon a report log of its own, since UBSan prints
  and carries on where ASan stops the daemon outright
- `test/lab.sh` takes `NETLINK=yes` to run its scenarios against
  such a build, and refuses to run if the tree it was pointed at was built
  the other way
- `test/pimsend.c` grew `-F`/`-E`, the address family and encoding type of
  the encoded group and source records alone, leaving the message's unicast
  addresses IPv4 -- which is how a parser that checks one and not the other
  is caught -- and `-0`, the zero dummy-header checksum a Null-Register may
  carry and the RP must not check
- `test/igmpv3.c` takes `-v 2` to send an IGMPv2 membership report instead
  of an IGMPv3 one.  A v2 report names a group and nothing else, which is
  the whole question where the group is in the SSM range, and a kernel join
  cannot be used to ask it: the kernel picks the version itself and follows
  whatever the querier on the LAN has negotiated
- New `static-rp` scenario in `test/lab.sh`: R3 is given an
  `rp-address` while R2 is the BSR, and the configured RP has to survive
  the Bootstrap and then outlive the BSR itself.  The two RPs are the same
  router under two addresses, so a configured entry that survived cannot be
  confused with one the BSR put back
- New `test/pimsend.c`, the counterpart of `test/igmpv3.c` on the PIM
  socket: it builds one PIM message -- hello, join, prune, bootstrap,
  candrp, register, regstop or assert -- sends it once and exits, with
  every field that can be got wrong exposed as an option: the version, the
  type nibble, the checksum, group and source mask lengths, the address
  family and encoding type bytes, the B and Z bits of an encoded group, and
  the holdtime.  Most of what `doc/rfc7761-compliance.md` lists could not
  be reproduced by a lab of pimds at all, two pimds sharing one reading of
  the wire, so a field pimd encodes wrongly it also decodes wrongly and the
  lab stays green
- New `crafted` scenario in `test/lab.sh`, the first user of it and
  a regression test for the whole packet format section of
  `doc/rfc7761-compliance.md` as well as for: a Join/Prune and a Bootstrap
  carrying a mask length no address has are refused, a unicast Bootstrap
  from a host that has sent no Hello is refused, and the RP set survives
  both.  Each has its positive control beside it -- the same Join correctly
  formed, and the same Bootstrap once its sender has said Hello -- because
  a parser that refuses everything passes every assertion about refusing.
  ED1 sends them, a host on a subnet the router has an interface on, which
  is the position RFC 7761 sec. 6.2 is about and all an attacker needs
- New `register-filter` scenario in `test/lab.sh` for
  `register-accept-from`: the RP is given a prefix that does not cover the
  address the DR registers from, which is its address on the sender's LAN
  and not the one the RP has in its neighbour table, and then one that
  does.  The two are told apart by the Register-Stop and by the DR's
  Register-Suppression timer.  Not by the RP's routing table, which holds
  entries for the group either way: the kernel decapsulates a Register
  before pimd is handed it, and the registering DR joins the shared tree
  itself, so the inner packets have somewhere to land even where nobody
  has joined the group.  The scenario asserts that, and counts the
  Registers the RP's kernel opened while pimd refused them, so the limit
  is measured rather than described
- `test/lab.sh` and `test/freebsd-interop.sh` run several
  scenarios at a time.  `-s SLOT`, 0 to 31, names everything a lab puts on
  the host after its slot -- jails, epairs, bridges, interface group, work
  directory, and in the interoperability lab the taps, the bhyve VM and
  the management subnet -- so labs in different slots cannot see or tear
  down each other, and `-j JOBS` runs that many scenarios at once, a slot
  each: on a 16-core host `-j 4 run all` takes 4m35s and `-j 14` 4m11s,
  where the sequential walk takes about half an hour.  `net.inet.ip.mcast.loop` is the one piece of host state the
  slots share, and it is now held between them under a lock, the last lab
  to stop putting the host value back -- before this, the first one to
  stop restored it under every other.  `test/veos-bhyve.sh` keeps each
  VM's files in `$WORK/<name>`, two guests having never been able to share
  the one disk image
- The documentation says which pimd this is: the man pages, the READMEs and
  the RPM spec name <https://github.com/ocochard/pimd> as the project, with
  a `BUGS` section in each man page pointing bug reports and support
  questions at its issue tracker.  The repository pimd forked from is still
  named where it is the accurate reference -- its 2.x tarballs, its wiki,
  the issue numbers cited in code comments and in the tests -- but it carries
  none of the work here and is no longer given as the place to ask
- `pimd.conf(5)` is installed and packaged.  `man/Makefile.am` named only
  `pimd.8` and `pimctl.8`, so the manual page of the configuration file
  reached neither `make install` nor a release tarball, though `pimd.8`
  sends a reader to it three times
- The tag of a release is what the release is named after.  The workflow
  that publishes one read the whole ref where it wanted the tag, which
  would have called this release "pimd vrefs/tags/3.0.0", and it ran on
  actions that have reached their end of life
- The release tarball carries `doc/` again: the READMEs, the FAQ, the
  install notes, `TODO.org`, `rfc7761-compliance.md` and the security
  review prompt.  v2.3.2 shipped all of these from the top of the tree; the
  move to GNU Configure and Build put them under `doc/` and left
  `doc/LICENSE.mrouted` the only one named in `EXTRA_DIST`, so everything
  README.md points a reader at was missing from a release tarball.  The
  RFC texts and the papers beside them stay out, being reference copies of
  documents published elsewhere

### Fixes
- Remove undefined shifts UndefinedBehaviorSanitizer reported, and the
  same pattern it had not reached yet.  Reading a 32-bit field out of a
  PIM message, a Hello's GenID or DR priority, an Assert's metric,
  shifted a byte of 0x80 or more into the sign bit of an `int`; the
  fallback random seed was rotated by a shift of up to 2^32; the prefix
  length of a netmask and the walk over a routing socket reply's address
  bits shifted a 1 into the sign bit; and the vif and neighbor bitmaps
  did so for vif 31 and neighbors 31 and 63
- Fix a use after free on every reload, `SIGHUP` or `pimctl restart`, of a
  router holding (S,G) state.  Rebuilding the routing table freed the head
  of the source list before deleting the groups, and deleting a group
  unlinks from that head every source it leaves with no entry.  On Linux
  glibc caught the write and aborted pimd; on FreeBSD it went unnoticed.
  A source still listed with no entry at all, if there is one, is freed
  now as well rather than leaked.  Found by the `keepalive` scenario of `test/lab.sh` on
  Linux, and pinned down by building pimd with AddressSanitizer on both
- On Linux, send the route's metric in a PIM Assert.  The route lookup
  `netlink.c` makes is answered with the route resolved for the address,
  and Linux never puts the metric in that answer, so every Assert said 0
  and the election fell through to the addresses, as it did before the
  metric was taken from the routing table at all.  pimd now asks for the
  routing table entry itself, with `RTM_F_FIB_MATCH`, when the answer has
  no metric; the next hop is still the one the ordinary lookup picked.
  FreeBSD's netlink always puts the metric in, so nothing changes there.
  Found by the `shared-lan` scenario of `test/lab.sh` run on Linux
- Keep (S,G,rpt) state apart from (S,G) state, as RFC 7761 sections 4.5.3,
  4.5.6 and 4.5.7 do.  A Prune(S,G,rpt), which takes one source off the
  shared tree on an interface, was applied to the (S,G) Join state there
  instead, so on a LAN it cancelled the Join(S,G) another router still
  wanted, and a Prune(S,G) took the source off what the interface got from
  the shared tree too.  A Join(S,G,rpt) was ignored, and pimd never sent one,
  so no router on a LAN could override another's Prune(S,G,rpt) and a router
  that wanted a source back after pruning it waited for the next periodic
  Join(*,G).  A Prune(S,G,rpt) now waits out the override interval before
  it takes effect, a Join(S,G,rpt) cancels it, a Join(*,G) cancels every one
  it does not carry, and pimd sends the Join(S,G,rpt) that overrides a
  neighbour's Prune or takes back its own.  `pimctl show mrt detail` shows
  the state as `RptPrune oifs`
- A router downstream of an assert election now sends its Joins to the
  winner.  On its RPF interface pimd measured each Assert against its own
  route to the RP instead of simply losing to it, as RFC 7761 section 4.6.2
  has a router there do, so a downstream router nearer the RP than the
  contenders kept joining the loser, and each Join took the loser out of
  its Loser state: the LAN flapped between the two routers once a
  Join/Prune period.  When that Loser state ends, the Joins go back to the
  router the routing table names
- Offer local memberships to PIM again when a group range gains an RP.  A
  membership report for a group without an RP was recorded and nothing
  more until the host reported again, up to a query interval later, which
  is where a router that has just started usually is
- An RP that receives a Register for a source nobody has joined yet starts
  the Keepalive Timer with its Register-Stop, as RFC 7761 section 4.4.2
  asks, and joins the source as soon as a receiver appears.  It used to
  keep nothing, so that receiver waited for the first hop router to
  register again, 30 to 90 seconds.  Where the SPT threshold is not zero it
  sends no Register-Stop at all
- Run the Prune-Pending Timer of RFC 7761 section 4.5.1 and the Assert Timer
  of section 4.6 to the millisecond.  An upstream router let an interface go
  5 to 10 seconds after a Prune nobody overrode, where the section asks for
  the J/P_Override_Interval, 3 seconds on defaults, and an assert winner
  resent its Assert after 175 seconds, not Assert_Time less
  Assert_Override_Interval, 177; a loser's Assert_Time could end 5 seconds
  early, before a winner resending at 177 seconds had refreshed it
- Send triggered Joins and Prunes when the state changes, not on the next
  5-second tick, and time the override Join of RFC 7761 section 4.5.4 to
  the millisecond.  The Join Timer was a count of seconds aged once per
  tick, so a join or prune, the switch to the shortest path tree included,
  went out up to 5 seconds late, and t_override came down to the tick
  phase: an override could reach an upstream router after the 3 seconds it
  waits before acting on a Prune.  The callout queue counts milliseconds
  on the monotonic clock now, and a Join Timer due before the next tick
  gets a pass of its own.  pimd advertises the 0.5 second Propagation_Delay
  default again, where it advertised 5 to make up for the tick, and a
  Prune is sent once on the transition to NotJoined instead of every
  minute
- Delay the Hello answering a new or restarted PIM neighbor by a random 0
  to 5 seconds, the Triggered_Hello_Delay of RFC 7761 section 4.3.1, so a
  LAN does not answer a rebooting router all at once.  The Bootstrap a DR
  unicasts to the neighbor, RFC 5059 section 3.5, now follows that Hello
  rather than an immediate one, and a Join/Prune or Assert sent on the
  interface in the meantime sends the Hello first
- Send and use the Hello Address List option, RFC 7761 sec. 4.3.4.  An
  interface with more than one address now lists the others in its Hello,
  and the lists neighbors send are kept, so a route whose next hop is a
  neighbor's secondary address finds that neighbor.  pimd used to log
  "NOT A PIM ROUTER" for such a route and never join through it, and a
  neighbor routing through one of pimd's own secondary addresses could not
  tell which router it belonged to.  `pimctl show neighbor detail` lists
  each neighbor's secondary addresses
- Suppress a periodic Join(\*,G) that another router on the upstream link
  has just sent, RFC 7761 sec. 4.5.4, for the smaller of t_suppressed and
  the HoldTime of the Join overheard.  The timer assignment had been
  removed after a report of groups lost for minutes at a time, so every
  router on a LAN sent its own Join(\*,G) every minute.  That loss is what
  suppression outliving the upstream router's state looks like, and the
  HoldTime bound, which was missing, is what prevents it.  The (S,G) branch
  follows the same rule, and neither compares the Join Timer against the
  HoldTime nor breaks ties on addresses any more, which the RFC does not do
- Move the groups a newly learned group range covers onto its RP, RFC 7761
  sec. 4.7.1.  The mapping of a group was recomputed only when the range it
  sat on changed, so a longer range learned after its groups had state, say
  225.1.2.0/24 beside an existing 224.0.0.0/4, left every one of them on
  the shorter range's RP until the group was torn down.  Two routers that
  learned the same ranges in a different order sent Joins and Registers for
  the same group to different RPs
- Set the No-Forward bit on the Bootstrap pimd unicasts to a new neighbour,
  and honour it on one received, RFC 5059 sec. 3.5.1.  That copy is the
  quick refresh a DR hands a router that has just come up, and the bit is
  what tells the receiver to skip the RPF check and not pass it on; pimd
  sent it as a plain Bootstrap with the byte zeroed and never read the byte
  either.  Both halves went wrong the same way: a No-Forward Bootstrap from
  a conformant neighbour was put through the very check the bit waives, so
  the refresh was dropped unless the sender happened to be the RPF
  neighbour toward the BSR -- and if it was, the forwarding loop copied it
  out of every other interface with the bit still set, telling every router
  downstream to accept it without an RPF check of its own.  A Bootstrap
  unicast to this router is no longer forwarded either, which sec. 3.4 also
  asks.  What is still required of a No-Forward Bootstrap is a Hello from
  its sender: waiving the RPF check does not waive sec. 6.2
- Keep the register vif out of the outgoing interfaces of a directly
  connected source in the SSM range.  RFC 7761 sec. 4.8.1 rule 3 has no
  Register for such a group and `send_pim_register()` never built one, so
  nothing went on the wire -- but `process_cache_miss()` added the vif to
  any (S,G) this router is the DR for unless it was the RP for the group,
  and for an SSM group the RP is the link-local address pimd invents, never
  this router.  Nothing took it back out either: the Register-Stop that
  prunes it for an ASM source cannot arrive for a group nobody is the RP
  of.  The kernel therefore raised an upcall for every packet of every such
  stream and the daemon dropped each one, which is the whole SSM data rate
  of every directly connected source crossing into user space and back, on
  the one router in the domain guaranteed to see all of it
- Answer a Register for a group in the SSM range with a Register-Stop, the
  second half of RFC 7761 sec. 4.8.1's rule for one.  pimd refused to
  forward such a Register, which is the first half, and called
  `send_pim_register_stop()` for the second -- but that function returned
  before building anything when the inner group was in the range, a guard
  left from when pimd itself might have registered an SSM group.  So a
  legacy DR was told nothing, kept encapsulating at the full data rate, and
  the RP kept parsing and discarding one Register per packet for as long as
  the source sent
- Ignore a (\*,G) or (S,G,rpt) Join/Prune for a group in the SSM range,
  RFC 7761 sec. 4.8.1 rule 4: a router MUST NOT forward packets based on
  (\*,G) state for such a group, and the (\*,G) macros are NULL there.
  pimd never built that state on its own -- `add_leaf()` picks (S,G) inside
  the range and `join_or_prune()` refuses to send for a (\*,G) in it -- but
  the receive path had no range test, so a Join(\*,G) naming the right RP
  built one, and `calc_oifs()` merges a (\*,G)'s outgoing interfaces into
  every (S,G) of the group, which is the forwarding rule four forbids.  The
  RP such a Join must name is the link-local one pimd invents for an SSM
  range, which no router that learned its RP set from the BSR would send,
  and one that maps SSM groups to an RP of its own would
- Discard a PIM message whose version is not 2, or whose destination is not
  one the table of RFC 7761 sec. 4.9 gives its type: the section closes by
  requiring both, `accept_pim()` carried them as TODOs, and every message
  pimd sends writes a version that nothing read back.  A Hello, Join/Prune
  or Assert unicast to a router was acted on as though it had arrived on
  ALL-PIM-ROUTERS -- three handlers mark the destination unused in their
  signatures -- and a Candidate-RP-Advertisement multicast to
  ALL-PIM-ROUTERS was taken just the same.  A Bootstrap is the one type
  with two answers, RFC 5059 sec. 3.5.2 having the DR unicast the RP set to
  a router that has just come up
- Refuse an encoded address whose address family or encoding type is not
  IPv4 native, RFC 7761 sec. 4.9.1.  Both bytes were parsed into structure
  members nothing ever read.  The cost is not the address, which is garbage
  either way, but the length: an Encoded-Unicast is 6 bytes for IPv4 and 18
  for IPv6, and every walk over these messages is written around the IPv4
  strides, so a record declaring another family was read at offsets its
  fields are not at -- source counts and flags taken out of the middle of
  addresses.  Checked now in the Join/Prune, Bootstrap,
  Candidate-RP-Advertisement, Register-Stop and Assert parsers
- Refuse a group range whose B or Z bit is set.  The third byte of an
  Encoded-Group carries the Bidirectional-PIM bit and the admin-scope-zone
  bit, and pimd called the whole byte reserved: a Bidir range was installed
  as an ordinary PIM-SM one, so an RP was picked for it, Joins were sent
  toward that RP and traffic register-encapsulated to it, none of which a
  Bidir range means.  RFC 5059 sec. 3.6 says an implementation of one
  protocol must not treat the other's ranges as its own.  pimd has no scope
  zones either, so a range declaring itself one is refused rather than
  treated as global.  Only the range is refused, not the message
- Hold the state a Join/Prune with a Holdtime of 0xffff asks for instead of
  ageing it, RFC 7761 sec. 4.9.5: the receiver "SHOULD hold the state until
  canceled by the appropriate canceling Join/Prune message".  Both timers
  the holdtime raises are held, the outgoing interface timer and the entry
  timer -- holding one while the other ages is the state gone all the same.
  Counted down five seconds at a time they reached zero 18 hours later,
  which is neither "until canceled" nor long enough for the
  dial-on-demand links the value exists for.  The Hello side of the same
  sentinel was already kept
- Verify the dummy IP header checksum of a Null-Register, RFC 7761
  sec. 4.9.3: a non-zero Header Checksum SHOULD be checked and the
  Null-Register discarded if it is wrong, and a zero one MUST NOT be
  checked.  pimd read neither, so the source and group it took out of that
  header, and the Register-Stop and Keepalive Timer refresh they drive,
  rested on nothing.  The header length is bounded against what arrived
  before it decides how much to checksum
- Keep a statically configured RP when a Bootstrap arrives for the same
  group prefix, RFC 7761 sec. 4.7, "A PIM router MUST support the static
  configuration of group-to-RP mappings".  An `rp-address` with no group
  covers 224.0.0.0/4, which is the prefix a Candidate-RP advertised under
  `group-prefix 224.0.0.0 masklen 4` lands on, so the configured entry and
  the learned ones shared one group mask: the first Bootstrap stamped that
  mask with its own fragment tag and the garbage collector at the end of
  `receive_pim_bootstrap()` deleted every RP on it whose tag differed,
  which was exactly the configured one.  RFC 5059's withdrawal of a prefix,
  an RP count of zero, took it out the same way.  The result was not that
  the BSR overrode the static RP, which would be a defensible reading of a
  section that gives no precedence rule, but that the static RP ceased to
  exist: only a SIGHUP restored it, so a router whose BSR then died aged
  the learned RP set out and was left with no RP at all.  Entries from
  `pimd.conf` are now marked, skipped by the collector, kept when a prefix
  is withdrawn, and no longer given a mortal holdtime by an advertisement
  naming the same RP.  The learned RPs are kept beside the configured one
  and `rp_match()` picks between them as before
- Ignore an IGMPv1 or IGMPv2 membership report for a group in the SSM
  range.  Such a report carries no source list, and `accept_group_report()`
  takes the source of an SSM membership as an argument, so `igmp.c` passed
  the report's IP destination -- which for those versions is the group
  itself.  The membership was recorded under a source that is a multicast
  address, `add_leaf()` asked for an (S,G) with it, and `find_route()`
  allowed it because the valid-host test is waived inside the SSM range:
  the router was left holding a (232.1.1.1,232.1.1.1) entry, an RPF lookup
  for a class D address behind it, and, where that landed on a PIM
  neighbour, an upstream router to send a Join naming a multicast source
  to.  A v2 Leave did not undo it either, that path matching the stored
  source against the message's destination, 224.0.0.2 for a Leave.  RFC
  4607 has no any-source membership for such a group and RFC 4604 has the
  IGMPv3 spelling of one ignored, which pimd already did
- Refuse a mask length off the wire that is wider than an address, RFC 7761
  sec. 4.9.1: "The mask length MUST be equal to the mask length in bits for
  the given Address Family and Encoding Type (32 for IPv4 native) ... A
  router SHOULD ignore any messages received with any other mask length."
  The byte was taken on trust and handed to `MASKLEN_TO_MASK()`, which
  shifts by `32 - masklen`, so anything above 32 shifted by a negative
  amount -- undefined behavior rather than a wrong answer (C11 6.5.7p3, SEI
  CERT INT34-C).  In practice the shift count wrapped: a Bootstrap claiming
  mask length 200 for 224.0.0.0 installed 224.0.0.0/8, and one claiming 33
  installed 128.0.0.0/1, so a single message could put a group range nobody
  advertised over a whole domain's RP set.  A Join/Prune is now ignored if
  any encoded group carries a mask length above 32 or any encoded source
  carries one that is not 32; a Bootstrap is ignored if its hash mask length
  or any of its group ranges is wider than an address, the hash mask length
  before anything is committed or forwarded; a Candidate-RP-Advertisement
  skips such a group prefix and keeps the rest.  `MASKLEN_TO_MASK()` itself
  now clamps, so a call site that forgets is defined rather than undefined.
  The Bootstrap checks run in a pass of their own, before the BSR address,
  priority and fragment tag are committed and before the message is
  forwarded: the loop that reads the group ranges runs last of all, so a
  message rejected there had already moved the BSR and been flooded onward
- Ignore a unicast Bootstrap from a router no Hello has been received from,
  RFC 7761 sec. 6.2.  Join/Prune and Assert already asked, and a Bootstrap
  sent to ALL-PIM-ROUTERS has to come from the RPF neighbour toward the BSR,
  which is the same lookup; the unicast branch asked only that the sender be
  on a directly connected subnet, which every host on that subnet is.  Any
  of them could hand a booting router the RP set for the domain, and nothing
  in such a message is RPF checked before it is flooded onward.  The window
  RFC 5059 sec. 3.5.2 opens the unicast branch for is unaffected:
  `receive_pim_hello()` sends its own Hello on the same path immediately
  before the Bootstrap, so the Hello that makes the DR a neighbour is on the
  wire ahead of it, and a lost one costs one unicast delivery of the RP set
  rather than the RP set, the BSR flooding the same message periodically
- Answer `inherited_olist(S,G,rpt) == NULL` of RFC 7761 sec. 4.2.2 from the
  shared tree's outgoing interfaces rather than from whether a (\*,G) entry
  exists.  The two are not the same question, and the difference is the one
  case the third alternative of `Update_SPTbit(S,G,iif)` is there for: a
  last hop router that has lost an Assert on its own RPF interface holds a
  (\*,G) whose olist is empty, so nothing wants the packet on the RP tree,
  while the fourth alternative is false as well because the (\*,G) follows
  the Assert winner and the (S,G) keeps the MRIB next hop.  With all five
  alternatives false the SPTbit was never set -- not merely set late -- and
  `CouldAssert(S,G,I)` stayed false with it, so the router asserted as an
  RPT forwarder for the life of the entry.  Two routers on one LAN then
  each held Assert Winner on a different entry, one on its (S,G) and one on
  its (\*,G), and both went on forwarding the same stream: a duplicate on
  the segment that no further Assert could resolve.  The three terms
  sec. 4.1.3 subtracts from `inherited_olist(S,G,rpt)` are (S,G,rpt) state
  pimd does not keep, and all three only subtract, so an empty (\*,G) olist
  is an empty inherited olist whatever they would have removed.  Found by
  `shared-lan-spt` of `test/lab.sh`, which reproduces it under
  `-j 4 run all`
- Send and parse the LAN Prune Delay Hello option, RFC 7761 sec. 4.3.3,
  and derive the Prune-Pending Timer from it.  pimd advertised neither
  Propagation_Delay nor Override_Interval and kept neither from its
  neighbours, so every router on a link with pimd on it fell back to the
  defaults; worse, the delay pimd itself waited before acting on a Prune
  was the Join holdtime divided by three, 70 seconds for the usual 210 and
  about six hours for a Join asking for 0xffff.  A Prune on a shared LAN
  therefore left traffic flowing long past the three seconds
  J/P_Override_Interval(I) asks for, compounding at every hop, while an
  outgoing interface that came from a local member rather than from a
  received Join went the other way and was dropped instantly, with no
  override window at all.  Both are now the interval the link negotiates,
  zero where pimd has at most one neighbour on the interface, and the
  PruneEcho of sec. 4.5.1 is sent when the timer expires so that an
  override lost on the LAN can still be made.  The Propagation_Delay pimd
  advertises is the 5 second timer granularity rather than the 0.5 second
  default, which is the lower bound sec. 4.3.3 asks implementers to enforce
  "to allow for scheduling and processing delays within their router": a
  triggered Join here is built by the periodic pass, so an upstream told to
  wait 3 seconds would stop forwarding before pimd's own override could go
  out
- Do not split the group set carrying a (\*,G) Join across two Join/Prune
  messages.  RFC 7761 sec. 4.9.5.2 makes the list of (S,G,rpt) Prunes that
  qualifies such a Join unsplittable: an upstream router that reads the
  Join(\*,G) without the prunes moves every (S,G,rpt) it holds for the group
  to NoInfo, and the sources in the tail flood the shared tree until the
  next period repeats the mistake.  pimd flushed on message size alone,
  which above roughly 65 pruned sources did exactly that.  The group sets
  already packed are now sent first so the split falls between sets, and
  where even a message of its own is not enough the section's own rule
  applies: the numerically smallest N source addresses are sent and the
  rest left out
- Keep the olist PIM forwards off apart from the one it makes Join/Prune
  decisions with.  `lost_assert(S,G,I)` of RFC 7761 sec. 4.6.5 asks, as its
  third term, whether the assert winner would still beat the metric this
  router will have once it reaches the shortest path tree, and the Note
  under the macro says the term exists for the phase before SPTbit is set.
  pimd asked it only once the bit *was* set and used one olist for both
  purposes, so a router that lost an assert while still forwarding on the
  shared tree pruned the very source whose traffic would have taken it to
  the shortest path tree, and the two never resolved
- Let an Assert reach the (S,G) state machine that owns it after the (\*,G)
  has lost the interface.  Sec. 4.6.1 gates the NoInfo-to-Loser transition
  on AssertTrackingDesired(S,G,I), which is join and membership state;
  pimd asked instead whether the interface was still in the entry's
  outgoing list, which it never is once an assert has taken it, so a last
  hop router held on the shared tree beside one on the shortest path tree
  recorded the loss on its (\*,G) and re-ran the election every 180
  seconds.  An AssertCancel now reaches both machines, which is what the
  ordering of sec. 4.6.2 cannot express on its own
- Stop leaving a multicast group on whatever interface the kernel picks.
  `k_leave()` named the interface by the address the VIF was built with,
  and on \*BSD an address the kernel can no longer place is not an error:
  `INADDR_TO_IFP()` leaves the interface NULL and `imo_match_group()` then
  matches the group on *any* interface, so `IP_DROP_MEMBERSHIP` took the
  membership of whichever VIF came first in the socket's list.  An
  interface that was destroyed, or renumbered under the running daemon,
  therefore took 224.0.0.13, 224.0.0.2 and 224.0.0.22 off a VIF nobody had
  touched: pimd went deaf on the link it still had, heard no further
  Hellos there, and the neighbour it already had aged out and never came
  back.  Renumbering showed the other half of the same bug, the membership
  that should have been dropped stayed behind and the re-join that follows
  failed with "Address already in use".  Both calls now name the interface
  by an address it still has, and ask the kernel for nothing once the
  interface has gone and taken its memberships with it.  Caught by the
  `ifgone` scenario of `test/lab.sh`; Linux names the interface by
  index and was never affected
- Ask a netlink attribute for its bytes before reading them.  `RTA_OK()`
  only says an attribute is no longer than what is left of the message, so
  a four byte one with no payload passes it, and `getmsg()` then read the
  outgoing interface index and the gateway address out of nothing.  Both
  are now checked the way the route metric already was.  The kernel is the
  only writer of these, so this is hardening and not a fix for anything
  seen on a running router
- Check the interface index of a kernel upcall against the interfaces that
  are in service before using it.  `process_cache_miss()` and
  `process_wrong_iif()` took `im_vif`, one byte of the message the kernel
  wrote, straight into `uvifs[]` -- an array of MAXVIFS entries of which
  only `numvifs` are live -- and the first use was the debug log that
  prints the interface name.  Same reasoning as the length check above, and
  the same caveat: the kernel is the only writer of that field, so this is
  hardening and not a fix for anything seen on a running router
- Pay for the bytes of a kernel upcall before reading them.  `accept_igmp()`
  admits anything an IP header long, and everything behind that was then
  read on trust: `process_kernel_call()` reads a `struct igmpmsg` that is
  only the same size by the kernel header's own admission of a "convenient
  similarity", and an `IGMPMSG_WHOLEPKT` upcall had `send_pim_register()`
  dereference an encapsulated IP header past it and then copy `ip_len`
  bytes -- a length out of that header rather than out of what arrived --
  into the Register sent to the RP.  The received length is a parameter of
  all three now, and a packet claiming more than the kernel delivered is
  dropped with a warning instead of sending whatever followed it in the
  receive buffer.  Not reachable from the wire, since the upcall branch
  needs the IP protocol field zeroed as only the kernel does it, which is
  why this is hardening rather than a fix for something seen
- Copy the ECN bits and the DSCP of an encapsulated packet into the
  Register that carries it, which RFC 7761 section 4.4.1 asks for and
  `send_pim_unicast()` had no way to express: the outgoing Type of Service
  byte was written once at startup and left at 0, so traffic a source had
  marked crossed the DR-to-RP path as best-effort Not-ECT and arrived at
  the RP with its marking gone.  The byte is a parameter of that function
  now, 0 for every other message it sends
- Put protocol 103, PIM, in the dummy IP header of a Null-Register rather
  than 17, UDP.  RFC 7761 section 4.9.3 gives the field's value, and an RP
  that inspects it can drop the probe, after which the DR re-adds the
  register tunnel every 60 to 90 seconds for as long as the source sends
- Refuse a `hello-interval` outside the 30 to 18724 seconds
  man/pimd.conf.5 documents, warn, and use the default, the way every
  other range check in `pimd.conf` behaves.  Only the ceiling was enforced,
  so 0 was accepted and had pimd announce a zero Holdtime -- the value that
  tells a neighbor the sender is going down -- in every Hello, and 1 to 29
  were accepted silently and dragged the hold-time down with them
- Send the Hello with Holdtime zero of RFC 7761 section 4.3.1 before a
  restart takes the interfaces down, so neighbors elect a new DR at once
  instead of waiting out the Neighbor Liveness Timer.  `cleanup()` already
  sent one on the way out and `renumber_vif()` sends one from the old
  address; `restart()`, reached from SIGHUP and from `pimctl restart`, is
  the remaining path where the interfaces are still up and able to send
- Delay the first PIM Hello on an interface by a random 0 to 5 seconds, the
  Triggered_Hello_Delay of RFC 7761 section 4.3.1.  A delay was drawn at
  startup, from the wrong range, and then thrown away: `start_vif()` went
  on to send a Hello itself and `send_pim_hello()` re-arms the timer, so no
  randomized value survived a single tick and every router's first Hello
  went out at t=0
- Draw the Join/Prune suppression interval from 1.1 to 1.4 times the
  periodic interval, 66 to 84 seconds, as the t_suppressed row of RFC 7761
  section 4.11 asks.  It was RFC 2362's range, 60 to 89, whose low end
  equals the periodic interval exactly, so a suppressed router could still
  send its own Join inside the very period it was suppressed for
- Draw t_override from the Override_Interval of RFC 7761 section 4.11, 2.5
  seconds, instead of RFC 2362's [Random-Delay-Join-Timeout] of 4.5, which
  is a different quantity
- Log the assert transition of RFC 7761 section 4.6.1 and 4.6.2 that had
  no log line, a loser returning to NoInfo because the winner restarted
  or stopped answering, and say which of the two it was.  Every other way
  out of the loser state already reported itself under `-d asserts`, and
  the one that did not was also the one nothing could be written a test
  against
- Give back the assert state a restarting PIM neighbor had won on the
  interface that neighbor is on, rather than on every interface whose
  recorded winner happens to hold the same address.  An assert from a
  neighbor is received on one link and can only have won an election
  there, so a router with two links numbered out of the same private
  range could have a neighbor restarting on one of them hand back an
  interface that the winner of the other link still held.  Looking at the
  one interface, and only where the routing entry holds assert state at
  all, also stops a neighbor that restarts -- or one sending a new
  generation ID with every hello -- from costing a walk of every
  interface of every routing entry to find nothing
- Record which router won a PIM assert when the election is decided,
  instead of re-deriving it later by comparing the winner against the
  address of the interface.  That address is not fixed for the life of a
  routing entry: an interface renumbered under a running pimd, a moved
  DHCP lease being the ordinary case, keeps every routing entry and every
  assert those entries hold, so a router that had won an election on the
  interface read its own winner state back as loser state.  It stopped
  resending its assert, stopped defending the interface when challenged,
  and never sent the AssertCancel of RFC 7761 section 4.6.4 when it
  stopped forwarding there.  Measured in the lab afterwards rather than
  predicted: what it costs is the wrong state and not the traffic.  A
  renumbered router tears its routing entry down and builds it again
  while the interface is bouncing, and the entry that comes back asserts
  from NoInfo like any other, so the segment settles on one forwarder
  either way.  The assert-recover scenario of test/lab.sh holds
  both halves of that, the deviation at assertion 7 and the convergence
  that happens regardless at assertion 8
- Discard a PIM assert whose group is not a multicast group, or whose
  source is not a valid host address.  `receive_pim_assert()` took both
  straight off the wire and used them as routing table keys, the
  `find_route(..., CREATE)` that records a lost election included, so a
  neighbor could seed a routing entry on a loopback, class E or multicast
  "source", or on a group outside 224.0.0.0/4, and have pimd carry those
  on through the RPF lookup and into the kernel forwarding cache.  Every
  other message pimd parses already screens both addresses, a register at
  its inner header and a join/prune once per group and once per source;
  this one did not.  The zero source of a (\*,G) assert, RFC 7761 section
  4.9.6, stays allowed: it is what tells pimd there is no (S,G) state
  machine to run
- Answer `JoinDesired(S,G)` of RFC 7761 section 4.5.5 with the source
  specific state it is made of, instead of with the outgoing interface
  list the (\*,G) lends the entry.  It gates `Update_SPTbit(S,G,iif)` of
  section 4.2.2, so one ordinary any-source receiver behind a last hop
  router was enough to set the SPT bit of a router that is forwarding off
  the shared tree.  Section 4.6.1 compares that bit before either metric,
  so on a shared LAN such a router beat one really on the shortest path
  tree and held the group on the longer path.  A Join(S,G) received from a
  downstream router and an IGMPv3 source-specific membership still set it,
  as does a source that is directly connected or an entry `spt-threshold`
  really switched; `spt-threshold infinity` now keeps the bit clear, which
  is what section 4.2.1 says an infinite threshold does
- Keep the PIM assert state per interface, the way RFC 7761 sections 4.6.1
  and 4.6.2 define it, instead of one winner and one timer for a whole
  routing entry.  Five gaps close with it.  The winner now arms its Assert
  Timer at `Assert_Time - Assert_Override_Interval` and resends, so a
  conformant loser is refreshed rather than restoring its interface every
  180 seconds and flooding the LAN with duplicates until the next
  election.  A winner that stops forwarding on an interface sends the
  AssertCancel of section 4.6.4, so the LAN converges at once instead of
  waiting `Assert_Time` out.  A loser acts on later asserts on that
  interface, an AssertCancel included; before, losing removed the
  interface from the outgoing list and every further assert on it was
  dropped.  A loser also returns to NoInfo when the winner's GenID changes
  or its Neighbor Liveness Timer expires, instead of holding the interface
  off for up to three minutes after the winner has gone.  And asserts lost
  on two LANs no longer share one expiry
- Evaluate a received assert against the join and membership state of the
  interface, which is the `AssertTrackingDesired(S,G,I)` of RFC 7761
  section 4.6.1, rather than requiring the entry to hold a kernel cache.
  That cache is torn down as soon as the outgoing interface list empties,
  which is what losing an assert does, so a router with join state but no
  traffic of its own ignored the election it had just lost and kept
  sending its Joins to the loser
- Run the two Assert state machines RFC 7761 defines, the (S,G) one of
  section 4.6.1 and the (*,G) one of section 4.6.2, in the order section
  4.6.2 requires, instead of one election on whichever entry the lookup
  returned.  A message now reaches the (*,G) machine only where the (S,G)
  machine holds no state on that interface and did not move, and the RPT
  bit says which machine may take it at all: an Assert with the bit clear
  is the (S,G) machine's, one with it set can put the (S,G) machine into
  the winner state but never into the loser state.  A router holding both
  (S,G) and (*,G) state for a group can therefore keep assert state for
  both on the same interface, where before the two shared one record and
  the answer depended on which entry happened to be the longest match
- Compute the third term of `lost_assert(S,G,I)`, RFC 7761 section 4.6.5:
  an interface lost to an assert returns to the outgoing list once the
  entry is on the shortest path tree and the winner's metric no longer
  beats the metric the router would assert with from there.  Before, the
  interface stayed out until the Assert Timer expired or the winner sent
  an AssertCancel, even where the router had become the one that would win
  the re-election.  Until SPTbit is set nothing changes: section 4.2
  forwards off `inherited_olist(S,G,rpt)` then, and that olist loses the
  interface to `lost_assert(S,G,rpt,I)`, which has no such term
- Take the metric a PIM Assert carries from the unicast routing table, as
  RFC 7761 section 4.6.3 requires, instead of always advertising the
  `metric` of `pimd.conf`.  Every RPF lookup now brings the route's metric
  back with the incoming interface and the next hop: the route priority on
  Linux, the per route metric on FreeBSD.  Before, every pimd in a domain
  advertised the same number, the metric comparison of section 4.6.1
  always tied and the highest address won every election, so multicast was
  pulled onto the long path around a LAN whatever the routing table said.
  The `metric` and `default-route-metric` settings remain, as the fallback
  for a system that reports no metric.  The metric preference beside it is
  still configured through `distance` and `default-route-distance`: it is
  the administrative distance of the routing protocol the route came from,
  and the routing socket does not report that.  A router that loses an
  election now also leaves the assert loser state as soon as its own
  metric becomes better than the winner's, the transition section 4.6.1
  defines for exactly this, rather than waiting up to `Assert_Time` for a
  routing change to take effect
- Reject an `altnet` or `scoped` masklen above 32 in `pimd.conf` instead
  of shifting by it.  `VAL_TO_MASK()` shifts by `32 - masklen`, so a
  larger value shifted by a number no 32-bit type has, which is undefined
  behaviour; the resulting mask was whatever the CPU happened to produce.
  Zero was already rejected for `scoped`, and for `altnet` it never
  reaches the shift, it is how the interface's own netmask is asked for
- A second `altnet` or `scoped` on the same `phyint` line, written
  without a prefix length, no longer inherits the length of the one
  before it.  The length was parsed into a variable set up once per line
  while the keywords are read one at a time, and a token with no `/len`
  left it untouched, so `altnet 10.0.0.0/8 altnet 10.1.2.0` gave the
  second entry a /8.  Each keyword is now read on its own, and one
  without a length falls back to the interface netmask, or is rejected
  for `scoped`, which has no such fallback
- Never accept a 127/8 address, whatever its netmask.  RFC 1122, section
  3.2.1.3, bans such an address from appearing outside a host, and the
  current special-purpose address registry, RFC 6890, records 127/8 as
  neither forwardable nor globally reachable, so it can never be a
  neighbor, an RP, a BSR, or a source pimd forwards -- RFC 7761 requires
  any RP address to be reachable from all routers in the domain, and the
  source address of a unicast PIM message to be domain-wide reachable.
  `inet_valid_subnet()` already rejected 127/8, but only as a subnet, and
  `config_vifs_from_kernel()` skips that check entirely for a /32, which
  has no subnet or broadcast address to compare against.  A `127.0.0.1/32`
  on an interface with the multicast flag set therefore became a VIF.  The
  check now lives in `inet_valid_host()`, which is applied to a /32 as
  well, so the RP, BSR, `phyint` and altnet addresses read from
  `pimd.conf`, and the sources taken from received Register and Join/Prune
  messages, are all covered by it too.  An address outside 127/8 on a
  loopback interface, the reason people put an RP or a source there, is
  unaffected
- Fix an out-of-bounds read on a long word in `pimd.conf`.  `next_word()`
  filled its 42 byte token buffer up to the last byte and returned it
  without a terminator, and every caller hands what it gets to
  `strcmp()`, `inet_parse()` or `strtonum()`, which then read on into
  whatever follows the buffer.  A 42 character token was enough, e.g. an
  over-long number, where `strtonum()` scans digits until one is not a
  digit and walked off the end.  Caught by AddressSanitizer as a
  `global-buffer-overflow` of `next_word.token`
- Notice on *BSD when an interface a VIF sits on is removed, issue #218.
  `check_vif_state()` read a removed interface as Linux's `ENODEV` only,
  so on FreeBSD, NetBSD and DragonFly the `SIOCGIFFLAGS` failure, `ENXIO`
  there, fell through to `logit(LOG_ERR)`, which exits the daemon.  It
  rarely got that far: the poll it sits in was gated on `vifs_down`, and
  nothing sets that when an interface is removed outright.  The addresses
  leave with it, so pimd's `IP_MULTICAST_IF` is silently ignored and the
  Hello goes out whatever route the kernel picks instead of failing with
  `ENETDOWN`.  The usual outcome was therefore worse than the crash: the
  VIF stayed in service indefinitely, naming an interface that no longer
  existed, with the kernel left holding forwarding state for it.  pimd now
  polls the interfaces unconditionally, takes the VIF out of service on
  either errno, and treats any other `SIOCGIFFLAGS` failure the same way
  rather than acting on interface flags the failed call never filled in.
  Covered by the new `ifgone` scenario of `test/lab.sh`
- Fix `update_reg_vif()` reading one past the last VIF when it logs that
  it cannot restart the register VIF.  The index it printed was left over
  from a loop that had run to completion, so it was `numvifs`, which is
  past the end of `uvifs[]` altogether once `MAXVIFS` interfaces are
  configured.  It now names the register VIF it failed to move
- Fix IGMPv3 (S,G) memberships that could never expire.  A group held a
  single membership timer, carrying whichever source had reported last.
  For an any-source group that is the whole story, but a group in the SSM
  range is a list of (S,G) memberships that come and go one at a time: a
  report for a second source rearmed the timer belonging to the first, and
  an IGMPv3 BLOCK for the source that had armed it cancelled the only
  timer the group had while leaving its other sources in place.  Nothing
  expired the group after that, on any timescale, so the memberships and
  the (S,G) forwarding state under them stayed until the interface went
  away.  A leave for the last source still cleaned up, which is why this
  only showed when a receiver stopped reporting rather than leaving.
  Every source now arms, refreshes and cancels a timer of its own, and
  `pimctl show igmp` prints each source's own timeout rather than the
  group's for all of them
- Bound the sources pimd keeps for one group, and the work one report can
  ask for.  Every source in an IGMPv3 group record is looked up in, or
  added to, the group's source list, and each one accepted is a
  membership, a timer and an (S,G) entry held until that source is blocked
  or times out.  RFC 3376 bounds neither: a single 64 KiB datagram carries
  some 16000 source addresses, so one packet from any host on the LAN
  walked a growing list once per source and left as many entries behind as
  it liked.  A group now keeps at most 256 sources, at most that many are
  acted on per group record, and both are logged when they bite
- Harden the paths that parse packets off the wire.  `accept_igmp()` and
  `accept_pim()` derived the IGMP and PIM message offsets from the IP
  header length without checking it, and the guard that looked like it
  covered this in `accept_igmp()` compared a value against its own
  definition and could never be true.  IGMP messages are now also
  discarded when the checksum is wrong, as RFC 3376 sec. 4.1.2 requires
  and as every `receive_pim_*()` already did.  In the IGMPv3 report
  parser, Aux Data Len is now scaled in 32-bit words per RFC 3376
  sec. 4.2.6 rather than counted as bytes, which had the walk to the next
  group record land inside the record it just parsed, on bytes the sender
  chooses, and read them as further records; the report header and each
  record header are bounded before the counts inside them are read.  On
  the housekeeping side, timer IDs are no longer stored in unsigned
  fields, where the -1 of a failed `timer_set()` read back as a running
  timer, `timer_set()` frees the callback data it was handed when it
  cannot create the timer, and the `init_igmp()` and `init_pim()` error
  paths no longer leave a freed buffer pointer or a closed descriptor
  behind for a later `restart()` to pick up
- Fix PIM Assert being sent with the RPT bit clear for a group the router
  only has (\*,G) forwarding state for.  RFC 7761 sec. 4.6.1 compares
  assert metrics with `rpt_bit_flag` first, and only a router whose
  `SPTbit(S,G)` is set may claim the shortest path tree metric, so a
  router forwarding off the shared tree has to lose to one that joined
  the source.  pimd took the bit from `MRTF_RP` on whichever entry it was
  forwarding off, and the (S,G) that a cache miss builds underneath a
  (\*,G) never carries it, so such a router claimed a tree it never
  joined, the metrics tied and the election was settled by the address
  tiebreak instead.  On a LAN with two forwarders this could leave the
  traffic on the shared tree and discard the shortest path copy.  Three
  parts: the metric now comes from one helper named after the spec's
  `my_assert_metric()`, shared by the send and receive paths that had
  three hand rolled copies of it; the receive path no longer reads the
  RPT bit as "this is a (\*,G) assert", which sent an (S,G) assert from an
  RPT forwarder to the (\*,G), where the absent kernel cache made it drop
  the assert and never resolve the duplicate; and `MRTF_SPT` is now set
  when (S,G) traffic arrives on `RPF_interface(S)` while the router holds
  joined oifs of its own, per sec. 4.2.2, instead of only when the (S,G)
  and (\*,G) incoming interfaces differ, which they never do where the
  path to the source and the path to the RP leave by the same interface
- Fix `I_am_RP()` tests being written against `my_cand_rp_address`, which
  is only ever assigned when parsing `cand_rp`.  On a router whose RP
  comes from a static `rp-address` in `pimd.conf` it stays 0.0.0.0, so
  the router that *is* the RP answered "no" to every internal test of
  whether it is one.  RFC 7761 sec. 4.4.2 defines `I_am_RP(G)` from the
  group-to-RP mapping, not from candidacy, so these now ask whether the
  group's RP address is local.  Visible effects: the RP no longer adds
  the register vif to the oif list of its own directly connected sources
  (it was encapsulating traffic to itself), no longer sends a Join/Prune
  towards S for an (S,G) with an empty oif list, which the end of RFC
  2362 sec. 3.3.2 says must not be sent, and no longer drops every
  Register when run with `-t TABLE_ID`
- Remove GNU:isms like `%m` and `__progname` to be able to build on
  systems that don't have them, like musl libc in e.g. Alpine Linux
- Issue #38: Allow enable `phyint` based on ifname or address.
- Issue #68: Do not enumerate VIFs for disabled interfaces. This fix
  allows using `pimd` on systems with more than 32 interfaces.
- Issue #84: Netlink code warns about missing VIF for disabled
  interfaces
- Issue #92: Fix RedHat/CentOS `.spec` file, building from GIT and
  from released tarball, by Sjoerd Boomstra
- Issue #93: Fixes a serious issue with the RP hash algorithm used in RP
  elections. The change makes `pimd` compatible with Cisco IOS, but it
  also makes `pimd` v3.0 *incompatible* with earlier `pimd`
  releases. Found and fixed by Xiaodong Xu
- Issue #251: Sources kept appearing and disappearing from the multicast
  routing table on a router acting both as DR for a directly connected
  source and as RP for the group.  With no members for the group the
  (S,G) outgoing interface list is empty, and the entry timer was only
  restarted for entries that had outgoing interfaces, so every entry was
  aged out a few seconds after a cache miss recreated it
- Issue #237: `igmp-querier-timeout` recommended the value the setting
  already had.  The recommendation was logged for any configured
  timeout, not only for one below the recommendation, and the checks ran
  while parsing the setting, so with `igmp-querier-timeout` ahead of
  `igmp-query-interval` in `pimd.conf` they compared against the default
  query interval instead of the configured one, warned, and replaced the
  timeout.  The pair is now checked once the whole file has been read,
  and `igmp-query-interval` no longer discards an already parsed
  `igmp-querier-timeout`.  Both settings are also range checked against
  the limits the man page documents, so an `igmp-query-interval 0` is no
  longer accepted, and both are reset to their defaults on `SIGHUP`, so
  removing either from `pimd.conf` now takes effect on reload
- Fix a Join scheduled against the wrong routing entry when overriding a
  neighbor's (\*,G) Prune.  RFC 7761 sec. 4.5.1 has a router that wants to
  keep receiving traffic override another router's Prune with a Join of
  its own, and pimd walks the group's (S,G) entries to schedule one per
  source.  It asked each source whether to join but then read and rearmed
  the (\*,G) Join/Prune timer instead of that source's, so the per-source
  override was never scheduled and the (\*,G) timer was rewritten once per
  source.  The equivalent loop on the (\*,\*,RP) path had it right
- Fix an undefined shift in the Cand-BSR bootstrap delay.  RFC 5059
  sec. 5 derives the initial timer from a log base 2, computed here by
  walking a mask down from the leftmost bit, and `1 << 31` on a signed
  `int` is signed overflow rather than that bit.  The mask is now built
  from an unsigned 1, as is the `2^31` the address term divides by
- Guard the DR election tiebreak against having recorded no neighbor.  A
  candidate is only kept when it beats the best priority seen so far,
  which starts at 0, so a segment where every neighbor advertises DR
  priority 0 leaves none recorded.  Reaching the tiebreak from there also
  needs our own priority to be 0, which `pimd.conf` currently refuses,
  so this was latent; the tiebreak now falls back on the head of the
  neighbor list, the highest address, which is the winner it looks for
- Let `utimensat()` be its own existence test when `pidfile()` refreshes
  an existing PID file, rather than asking `access()` first.  The two
  calls left a window for the path to change in between, `access()`
  answered for the real uid rather than the one the file is touched with,
  and the touch itself went unchecked, so a failed refresh was still
  reported as a success.  One syscall now does all of it, and a PID file
  that went missing is created again as before
- Issue #211: Fix a BSD router never learning the RP set from a bootstrap
  router on one of its own subnets, reported from a topology where every
  router is adjacent to the RP router.  `k_req_incoming()` in
  `routesock.c` went to the kernel even for an address on a directly
  connected subnet, and such a route carries no gateway, so the lookup
  came back with an incoming interface but no RPF neighbor.  Every caller
  reads that as "no route": `receive_pim_bootstrap()` drops a Bootstrap
  whose RPF neighbor is 0.0.0.0, so the router next to the BSR was the one
  router in the domain that never learned where the RP is.  It could not
  send the (\*,G) Join its receivers needed, and nothing was forwarded to
  them.  Such an address is now answered from the vif table instead, with
  the destination as its own RPF neighbor, the way `netlink.c` has always
  answered it on Linux.  Fix by Sylvain Meygret, now covered by the
  `rp-offpath` scenario of `test/lab.sh`
- Issue #236: Stop the BSD routing socket from filling the log with
  "Timeout waiting for reply from routing socket", reported from pfSense.
  Two separate causes, both in `k_req_incoming()`:

  The address in the message, 169.254.0.1, is pimd's own: `config.c`
  gives the SSM range a static RP there, on purpose, because nothing in
  169.254/16 is routed and the RP must never be reachable.  pimd then
  asked the kernel for a route to it on every RP lookup anyway.  Those
  lookups are now answered directly, as the failure they are, in both
  backends: the netlink one only knew to keep quiet about them, and still
  asked.  On a router with a default route the query used to *succeed*
  and leave the SSM RP entry pointing out of the default route, which is
  not a path to an address RFC 3927 sec. 2.7 forbids forwarding to; it
  now keeps no incoming interface, as it already did wherever the query
  failed.

  The timeouts for real addresses have a different cause.  Nothing reads
  the routing socket outside a lookup, while the kernel keeps broadcasting
  every routing change to it, so the receive buffer fills between lookups
  with messages nobody asked for.  Once it is full the kernel drops the
  reply to the next `RTM_GET`, and the queued messages are then read in
  its place until the wait runs out: a busy router that gets there stops
  resolving RPF entirely, one 100ms stall in the main loop at a time.
  The socket is now emptied before each query, and the timeout that
  remains is a debug message under `-d rpf` like every other failure in
  that function, not a warning
- Form the PIM adjacency with a neighbor whose Hello carries an option
  pimd does not know, or no options at all.  RFC 7761 sec. 4.9.2 requires
  that unknown options "be ignored and MUST NOT prevent a neighbor
  relationship from being formed"; `parse_pim_hello()` instead returned
  failure unless the last option it looked at was one of the three it
  implements, so a Hello that led with LAN Prune Delay, Address List,
  State Refresh, Bidir Capable or any private type was discarded whole
  and the adjacency silently never formed -- taking that neighbor's
  Join/Prune and Assert messages with it.  Only an option pimd does
  understand, arriving with a length it cannot have, now fails the Hello
- Treat a Hello with no Holdtime option as RFC 7761 sec. 4.3.2 says, by
  holding the neighbor for `Default_Hello_Holdtime`, rather than as the
  holdtime 0 of a router announcing it is going down.  The option block
  is zeroed before parsing, so "absent" and "zero" were the same value
  and a neighbor that omits the option -- which it may, the option is a
  SHOULD -- was deleted and re-created on every one of its Hellos,
  flapping the DR election and resetting the upstream neighbor of every
  routing entry pointing at it
- Notice when an interface is renumbered under pimd.  The addresses were
  read once, at start-up and on `SIGHUP`, while the periodic interface poll
  only ever looked at the flags, so after a renumbering -- a DHCP lease
  change, an `ifconfig` edit, a failover address moving -- pimd went on
  announcing and sourcing PIM from an address the kernel no longer had.
  Neighbors held that address for the full 105 second holdtime and could
  elect it DR, while pimd's own sends left by whatever route the kernel
  picked, so PIM on that interface stayed broken until someone reloaded.
  The poll now compares each VIF against the first address its interface
  carries, the same one `config_vifs_from_kernel()` builds the VIF on, and
  on a change says goodbye with a zero-holdtime Hello, takes the VIF out of
  service, updates the address, subnet, netmask and broadcast address, and
  puts it back in service -- which announces the new address, as RFC 7761
  sec. 4.3.1 requires.  Point-to-point links are left out: they carry a
  peer address too, and renumbering one still wants a `SIGHUP`
- Forward to local members only on an interface where this router is the
  DR, as `pim_include()` in RFC 7761 sec. 4.1.5 has it.  An IGMP report is
  heard by every PIM router on the subnet, and each of them added the
  interface to its outgoing interfaces, so on a LAN with two routers that
  both had state for the group the receivers got every packet twice until
  an assert election sorted it out -- and that election is only triggered
  by data arriving on the wrong interface.  The membership itself is still
  recorded whoever hears it; what is now conditional is whether it makes
  the interface an outgoing one.  A change of DR recomputes the entries
  with members on that interface, so the role moving does not leave the
  new DR waiting for an unrelated event to start forwarding
- Stop the Register storm two pimd routers could fall into.  RFC 7761
  sec. 4.4.1 says an RP should not send a Register-Stop with the source
  address zeroed, RFC 2362's "stop encapsulating every source of this
  group", and that a DR should nevertheless accept one, as a
  Register-Stop(S,G) for every source it is registering at the time.  pimd
  had both halves backwards: the RP sent the wildcard whenever a (\*,G)
  entry ran out of outgoing interfaces, and the DR handed the zero address
  to `find_route()`, which rejects it, so the message was dropped.  A DR
  and an RP that both ran pimd could therefore encapsulate and answer at
  data rate indefinitely.  The RP now names the source, and a wildcard
  Register-Stop from an older RP is applied to every (S,G) of the group
  that has the register vif in its outgoing interfaces
- Send the Register-Stop when the RP has nowhere to forward a source,
  whatever the entry's incoming interface.  RFC 7761 sec. 4.4.2 asks for
  an empty `inherited_olist(S,G)`; pimd also required the entry to be on
  the shared tree, which an (S,G) whose incoming interface points at the
  source is not.  Such an entry, what a downstream (S,G) Join leaves
  behind once it is pruned, matched neither that arm nor the one for an
  entry already on the shortest path tree, so the RP said nothing and the
  DR went on encapsulating the whole stream into a router that drops it
- Resume registering when the group-to-RP mapping changes.  RFC 7761
  sec. 4.4.1 has a DR cancel its Register-Suppression timer and re-add the
  register tunnel when the RP changes.  `remap_grpentry()` did neither,
  and its loop skipped exactly the entries a DR registers with, so a DR
  that was suppressing when the mapping changed stayed silent until the
  timer of an RP that is no longer ours ran out, up to 90 seconds.  A new
  receiver joining the new shared tree heard nothing for that long
- Only build routing state from a received Register where this router is
  in fact the RP for the group.  RFC 7761 sec. 4.4.2 puts everything but
  "send Register-Stop" inside its `I_am_RP(G) AND outer.dst == RP(G)` arm.
  pimd creates the (S,G) entry as soon as it sees a Register for a group
  it holds no (\*,G) for, deliberately, to save the DR a retry, but it did
  so before asking whether it is the RP.  Any host that could unicast to
  the daemon therefore made it allocate a source, a group and a routing
  entry for every (S,G) it named, each held for 210 seconds, with nothing
  rate limiting it.  The group-to-RP mapping and the address the Register
  was sent to are now both checked first; a Register that fails either is
  still answered with a Register-Stop, as the spec's other arm requires
- Stop advertising an assert metric learned from another router.  RFC 7761
  sec. 4.6.3 says the metric preference and metric a router puts in its own
  Assert are the unicast routing table's, for the source or for the RP;
  sec. 4.6.1 keeps what a winner asserted separately, as
  `AssertWinnerMetric`.  pimd had one pair of fields for both, so losing an
  assert on the incoming interface overwrote the entry's own metric with
  the winner's -- a metric that is, by construction, at least as good as
  ours, since it just beat it.  The router then offered that metric on
  every *other* interface and won elections it should have lost, taking
  over forwarding from a router genuinely closer to the source, and the
  assert timer running out did not put the metric back.  The winner's
  metric is now kept beside the entry's own and used only where the spec
  uses it, comparing the next Assert on that interface
- Keep the rest of a Join/Prune group set when its RP does not match ours.
  RFC 7761 sec. 4.5.1 drops a Join(*,G) naming the wrong RP on its own and
  says the "other source list entries, such as (S,G,rpt) or (S,G), in the
  same Group-Specific Set should still be processed"; it also has received
  Prune(*,G) messages "processed even if the RP in the message does not
  match RP(G)".  pimd discarded the group set three ways instead: when no
  RP-map covered the group at all, when the Join named an RP that was not
  the local match, and it ignored a Prune(*,G) whose RP differed.  During
  an RP change, which is exactly when a downstream router still advertises
  the old RP, that threw away that router's (S,G) Joins and all of its
  Prunes, so established shortest-path state on the interface expired and
  the source stopped; a router that had not learned an RP-map yet built no
  downstream state at all, not even for plain (S,G) Joins
- Send the Join when the upstream router changes, in the three cases where
  RFC 7761 asks for one and pimd sent nothing.  A next hop that moves to a
  different router on the same interface was retargeted silently, because
  the (\*,G) path asks `change_interfaces()` to flush a change it cannot
  see -- same incoming interface, same outgoing interfaces -- so the Joins
  kept going to the router no longer in use until the periodic timer came
  round.  An Assert that moves `RPF'(S,G)` to the winner left our
  downstream receivers unknown to it for the same period, where sec. 4.5.5
  shortens the Join Timer to `t_override`.  And a neighbor whose GenID
  changed has restarted and lost the Join state we sent it, which
  sec. 4.5.4 and 4.5.5 answer the same way; pimd noticed the GenID, said
  hello back, re-sent the RP-Set and left the trees alone.  Each of the
  three cost up to a full Join/Prune period of black-holed traffic, the
  GenID one on every upstream restart, in every topology
- Prune the old upstream router when the next hop changes.  RFC 7761
  sec. 4.5.4 and 4.5.5 pair the Join to the new `RPF'` with a Prune to the
  old one; pimd overwrote the neighbor and said nothing, at all three sites
  that retarget an entry, so after a unicast reconvergence or an RP remap
  the router we no longer use kept forwarding the group down our branch
  until its own downstream state expired -- the advertised holdtime, 210
  seconds.  On a topology with two paths that is three and a half minutes
  of duplicate delivery and an assert election to clear it.  A change
  caused by an Assert is deliberately left out, as the spec does: there the
  other router is on the same link and the assert has already settled who
  forwards.  The Prune is also skipped where the old upstream is a router
  that has just gone away, the teardown paths reaching the same code
- Move a routing entry onto the shortest path tree when the switch is
  made, instead of only marking it.  Data from S arriving on
  `RPF_interface(S)` while the entry still points at the RP is the switch,
  and pimd set the SPTbit, cleared the RP bit and reprogrammed the kernel
  with the new incoming interface -- but left the entry's own incoming
  interface and upstream router pointing at the RP.  The kernel was then
  right and pimd was not: the Join(S,G) it triggers went to the RP-ward
  neighbor and left by the RP-facing interface, and the next change to the
  outgoing interfaces pushed the RP-ward parent back down to the kernel,
  after which every packet from S arrived on a non-parent interface and
  was dropped until the unicast route to S changed.  Reached wherever the
  path to the source and the path to the RP leave by different interfaces,
  which in the test suite is the `rp-offpath` scenario.  The switch now
  goes through the same `Update_SPTbit()` conditions as every other, so a
  router that has to wait for an Assert(S,G) waits here too and sends one
- Stop a received Join(\*,G) from switching every source of the group onto
  its own tree.  RFC 7761 sec. 4.5.1 gives "Receive Join(\*,G)" two actions,
  both on the (\*,G) downstream state machine; pimd also walked the group's
  (S,G) entries and, for each, sent a Join(S,G) upstream, recorded the
  interface as (S,G) join state and set the SPTbit.  Three things came of
  that.  A router configured with `spt-threshold infinity`, which is how
  you ask to stay on the shared tree, switched to per-source trees anyway,
  since this path never consults it.  Entries whose incoming interface
  still pointed at the RP were marked as being on the shortest path tree,
  and an assert metric is chosen by that bit, so they asserted with the RPT
  bit clear and the metric of the route to the RP and beat the router that
  really was on the source tree.  And the join state it recorded had no
  timer to age it, so the next pass cleared the interface again and
  reprogrammed the forwarding cache, once per source per Join.  The
  interface reaches those entries through `inherited_olist()` without any
  of that; recomputing them, which is what the code says it is there to do,
  is all that is left.  This undoes half of the issue #67 optimization
  above, the half that built forwarding state for the inherited (S,G)
  entries; Joins for the entry the message is actually about are still
  sent without waiting for the timer
- Decide the (S,G) SPTbit by the conditions RFC 7761 sec. 4.2.2 gives for
  `Update_SPTbit()`, one of which pimd had the wrong way round.  The spec
  raises the bit when the packet arrives on `RPF_interface(S)`, the router
  wants the source, and -- among other alternatives -- the upstream router
  toward the source and the one toward the RP are *the same*.  pimd raised
  it when they *differ*, which is the one case the spec singles out to wait
  for an Assert(S,G) instead, so the router claimed the shortest path tree
  before the state upstream existed and asserted with a metric for a tree
  it had not joined.  The matching gap was at the other end: where the two
  agree, which is every chain topology, the bit was never raised at all
  unless the router had a downstream Join of its own, so a last-hop router
  whose receivers are local IGMP members never sent the (S,G,rpt) Prune,
  and the RP and every router on the shared tree carried that source
  forever.  Both now follow the pseudocode, together with the
  directly-connected, differing-RPF-interface and assert-loser
  alternatives; the one left out is `inherited_olist(S,G,rpt)`, which needs
  (S,G,rpt) state pimd does not keep
- Clear the (S,G) SPTbit when the entry has nowhere left to forward,
  instead of when a routing change points its incoming interface back at
  the RP.  The second rule is RFC 2362 sec. 2.10's; RFC 7761 sec. 4.2.2
  leaves `JoinDesired(S,G)` going false as the only thing that clears the
  bit, and its own condition 4 would in fact *set* the bit in the case
  pimd used it to clear it -- where the path to the source and the path to
  the RP leave by the same interface.  So a unicast reconvergence dragged
  an established shortest-path entry back onto the shared tree: the assert
  metric flipped from the source's to the RP's mid-election, the
  (S,G,rpt) Prune already sent was never refreshed, and the group
  re-flooded down the shared tree.  An entry whose outgoing interface list
  has just emptied now clears the bit instead, so it stops claiming a tree
  it is about to prune itself off
- Re-evaluate the (S,G) SPTbit while data is flowing, instead of only when
  the kernel raises an upcall.  RFC 7761 sec. 4.2.2 runs
  `Update_SPTbit(S,G,iif)` on receipt of every data packet, but pimd
  forwards in the kernel and only sees the packets the kernel hands up, so
  the check ran from the cache-miss and wrong-iif paths alone.  An MFC entry
  installed with the incoming interface the (S,G) already wants raises
  neither, so whatever was true at the first upcall was what the entry kept:
  an (S,G) that gained an outgoing interface a moment after its first
  packet, or one that the spt-threshold poll created under a (\*,G) and
  inherited the kernel cache of -- a last hop router that reaches the source
  and the RP through the same interface, which is every chain topology --
  stayed on the shared tree for as long as that cache lived.
  `CouldAssert(S,G,I)` is false without the bit, so every Assert such a
  router sent carried the RPT bit that sec. 4.6.1 compares before either
  metric, and it lost the LAN to any router that had reached the shortest
  path tree whatever its own metric said.  `age_routes()` now runs the same
  check once a pass for the entries that could still set the bit, asking the
  kernel whether the MFC entry carrying the (S,G) forwarded anything since
  the previous pass: the kernel matches packets on the incoming interface of
  the entry holding that cache, so a counter that moved on an entry whose
  iif is `RPF_interface(S)` is the arriving data sec. 4.2.2 asks about
- Bound a received Register-Stop before parsing it.  RFC 7761 sec. 4.9.4
  gives the message an encoded group and an encoded unicast source after
  the PIM header, 18 bytes in all, and `receive_pim_register_stop()` read
  all of them; `pim.c` guarantees only the 4 byte header, and the checksum
  over a 4 byte message covers just that header, so a Register-Stop
  truncated to its header passed every check and the (S,G) it named was
  read from whatever the previous packet had left in the receive buffer.
  A sender able to place a larger PIM packet in that buffer first chose
  the pair that came out, and where it matched a live entry and the
  source address was that group's RP, registering for that source was
  suppressed for the next 30 to 90 seconds.  Now checked against a
  `PIM_REGISTER_STOP_MINLEN` spelled as the fields being read, like the
  Assert, Join/Prune, Bootstrap and Cand-RP-Adv parsers next to it
- Only accept a Join/Prune or an Assert from a router a PIM Hello has been
  seen from, as RFC 7761 sec. 4.5 and sec. 4.6 both ask.  The one check
  either path made was that the sender sits on one of our subnets, which
  any host there does: a forged Join pulled a group onto the link for the
  210 seconds of its holdtime, a forged Prune removed an outgoing
  interface real routers still wanted, and a forged Assert claiming
  metric 0 took a group off the LAN for the 180 seconds of the assert
  timeout, all repeatable and none of it requiring a PIM adjacency.  Note
  that the configuration option both sections recommend, for peers that
  fail to send Hellos on point-to-point links, is not implemented; such a
  peer's Join/Prune and Assert messages are now ignored
- Fix a routing entry left naming a PIM neighbor that has just been freed.
  A router that loses an Assert on its incoming interface points the entry
  at the assert winner, which is by construction a different neighbor from
  the one its source or RP entry names -- that difference is the branch
  condition.  `delete_pim_nbr()` repaired only the entries reachable
  through the source or the RP, plus one (\*,G) case, so the winner's own
  entries kept a pointer into freed memory and the next Join/Prune pass
  wrote through it.  A neighbor on the LAN could arrange both halves: win
  an assert, then leave, or simply send a Hello with holdtime 0.  The
  repair now walks every entry, by way of the group list every entry is
  linked into, and puts back the next hop the unicast routing table gives,
  as RFC 7761 sec. 4.6.1 asks when the assert winner's liveness timer
  expires.  The assert metric goes back with it, so the router stops
  advertising a metric it copied from the winner
- Fix the message pimd exits with when no interface is usable.  It chose
  between "no enabled vifs" and "only one enabled vif" on a count that
  starts at one for the register vif and is only ever incremented, so the
  first arm could not be reached and the second one printed for a router
  with no enabled phyint at all -- counting the register vif, which
  cannot forward anything, as the one interface it had


[v2.3.2][] - 2016-03-10
-----------------------

Bug fix release. All users should upgrade, in particular FreeBSD users!

### Changes
- Minor code cleanup and readability changes to simplify the code.
- Update to libite v1.4.2 with improved `min()`/`max()` macros
- Use `-Wextra` not `-Werror` in default `CFLAGS`, this to ensure that
  pimd still builds OK on newer and more pedantic compilers
- Update man page and example `pimd.conf` with details on `rp-candidate`
  `bsr-candidate`, two very important settings for correct operation.

### Fixes
- Issue #57: Multicast routing table not updated on FreeBSD.  Introduced
  with issue #23, in pimd v2.2.0.  Too intrusive changes altered
  handling (forwarding) of PIM register messages.  This only affects BSD
  systems, in particular FreeBSD 10.2 (current), or any FreeBSD < 11.0
- Issue #63: Mika Joutsenvirta <mika.joutsenvirta@insta.fi> found and
  fixed serious issues with the PIM Assert timeout handling.
- Issue #65: Missing slash in config file path when using env. variable
- Issue #66: Make it possible to run `pimd` without a configuration
  file. If `pimd` cannot find its configuration file it will use
  built-in fallback settings for `bsr-candidate` and `rp-candidate`.
  This to ensure you do not end up with a non-working setup.  To disable
  `bsr-candidate` and `rp-candidate`, simply leave them out of your
  config file, and make sure `pimd` can find the file.
- Issue #69: Rate limit only what is actually logged. The `logit()`
  function counted filtered messages, causing long periods of silence
  for no reason. Fix by Apollon Oikonomopoulos <apollon@skroutz.gr>


[v2.3.1][] - 2015-11-15
-----------------------

Bug fix release.

### Changes
- Let build system handle missing libite GIT submodule
- Issue #61: Debian packaging moved to https://github.com/bobek/pkg-pimd

### Fixes
- Issue #53: Build problem with Clang on FreeBSD
- Issue #55: Default config uses `/etcpimd.conf` instead of
  `/etc/pimd.conf`. Slashes added and now `pimd -h` lists the default
  path instead of a hard coded string.
- Issue #60: Fix minor spelling errors.


[v2.3.0][] - 2015-07-31
-----------------------

*The PIM-SSM & IGMPv3 release!*

The significant new features in this release were made possible thanks
to the hard work of Markus Veranen <markus.veranen@gmail.com> and Mika
Joutsenvirta <mika.joutsenvirta@insta.fi>.

Tested on Ubuntu 14.04 (GLIBC/Linux 3.13), Debian 8.1 (GLIBC/Linux
3.16), FreeBSD, NetBSD, and OpenBSD.

### Changes and New Features
- Support for PIM-SSM and IGMPv3, by Markus Veranen
- IGMPv3 is now default, use `phyint ifname igmpv2` for old behaviour
- Default IGMP query interval has changed from 125 sec to 12 sec

  In `pimd.conf: igmp-query-interval <SEC>`

- Default IGMP querier timeout has changed from 255 sec to 42 sec

  In `pimd.conf: igmp-querier-timeout <SEC>`

- The built-in IGMP *robustness value* changed from 2 to 3
- Support for changing the PIM Hello interval, by Markus Veranen

  In `pimd.conf: hello-interval <SEC>`

- Support for multiple multicast routing tables, and running multiple
  pimd instances, by Markus Veranen. (Only supported on Linux atm.)
- Support for advertising, and acting upon changes to, Generation ID
  in PIM Hello messages, by Markus Veranen
- Support for advertising *DR Priority* option in PIM Hello messages.
  If all routers on a LAN send this option this value is used in the
  DR election rather than the IP address. The priority is configured
  per `phyint`. This closes the long-standing issue #5.
- Distribution archive format changed from XZ to Gzip, for the benefit
  of OpenBSD that only ships Gzip in the base system.

### New pimd.conf syntax!

The `pimd.conf` syntax has been changed in this release. Mainly, the
configuration file now use dashes `-` instead of underscore `_` as word
separators. However several settings have also been renamed to be more
familiar to commands used by major router vendors:

- `bsr-candidate`: replaces `cand_bootstrap_router`
- `rp-candidate`: replaces `cand_rp`
- `group-prefix`: replaces `group_prefix`
- `rp-address`: replaces `rp_address`
- `spt-threshold`: replaces the `switch_register_threshold` and
  `switch_data_threshold` settings
- `hello-interval`: replaces `hello_period`
- `default-route-distance`: replaces `default_source_preference`
- `default-route-metric`: replaces `default-source-metric`

Also, for `phyint` the `preference` sub-option has been replaced with
the less confusing `distance` and `ttl-threshold` replaces `threshold`.
See the README or the man page for more information on the metric
preference and admin distance confusion.

> **Note:** The `pimd.conf` parser remains backwards compatible with the
>           old syntax!

### Compile Time Features

The following are new features that must be enabled at compile time,
using the `configure` script, to take effect.  For details, see
`./configure --help`

- `--prefix=PATH`: Standard prefix to be used at installation, default
  `/usr/local`
- `--sysconfdir=PATH`: Prefix path to be used for `pimd.conf`, default
  `/etc`, unless `--prefix` is given.
- `--embedded-libc`: Enable uClib or musl libc build, on Linux.
- `--disable-exit-on-error`: Allow pimd to continue running despite
  encountering errors.
- `--disable-pim-genid`: Disable advertisement of PIM Hello GenID, use
    for compatibility problems with older versions of pimd.
- `--with-max-vifs=MAXVIFS`: Raise max number of VIFs to MAXVIFS.  
    **Note:** this requires raising MAXVIFS in the kernel as well!  Most
    kernels cannot handle >255, if this is a problem, try using multiple
    multicast routing tables instead.
- `--disable-masklen-check`: Allow tunctl VIFs with masklen 32.

### Fixes
- Fix issue #40: FTBS with `./configure --enable-scoped-acls`
- Properly support cross compiling. It is now possible to actually
  define the `$CROSS` environment variable when calling `make` to
  allow cross compiling pimd. Should work with both GCC and Clang.
  Tested on Ubuntu, Debian and FreeBSD.


[v2.2.1][] - 2015-04-20
-----------------------

### Fixes
- Fix another problem with issue #22 (reopened), as laid out in issue
  #37.  This time the crash is induced when there is a link down event.
  Lot of help debugging the propblem by @mfspeer, who also suggested
  the fix -- to call `pim_proto.c:delete_pim_nbr()` in
  `vif.c:stop_vif()` instead of just calling free.
- Fix issue with not checking return value of `open()` in daemonizing
  code in `main()`, found by Coverity Scan.
- Fix issue with scoped `phyint` in `config.c`, found by Coverity
  Scan. `masklen` may not be zero, config file problem, alert user.


[v2.2.0][] - 2014-12-28
-----------------------

### Changes
- Support for IP fragmentation of PIM register messages, by Michael Fine,
  Cumulus Networks
- Support `/LEN` syntax in `phyint`, complement `masklen LEN`, issue #12
- Support for /31 networks, point-to-point, by Apollon Oikonomopoulos
- Remove old broken SNMP support
- OpenBSD inspired cleanup (deregister)
- General code cleanup, shorten local variable names, func decl. etc.
- Support for router alert IP option in IGMP queries
- Support for reading IGMPv3 membership reports
- Update IGMP code to support FreeBSD >= 8.x
- Retry read of routing tables on FreeBSD
- Fix join/leve of ALL PIM Routers for FreeBSD and other UNIX kernels
- Tested on FreeBSD, NetBSD and OpenBSD
- Add very simple homegrown configure script
- Update and document support for `rp_address`, `cand_rp`, and
  `cand_bootstrap_router`
- Add new `spt_threshold` to replace existing
  `switch_register_threshold` and `switch_data_threshold settings`.
  Cisco-like and easier to understand

### Fixes
- Avoid infinite loop during unicast send failure, by Alex Tessmer
- Fix bug in bootstrap when configured as candidate RP, issue #15
- Fix segfault in `accept_igmp()`, issue #29
- Fix default source preference, should be 101 (not 1024!)
- Fix issue #23: `ip_len` handling on older BSD's, thanks to Olivier
  Cochard-Labbé
- Fix default prefix len in static RP example in `pimd.conf`
- Fix issue #31: Make IGMP query interval and querier timeout configurable
- Fix issue #33: pimd does not work in background under FreeBSD
- Fix issue #35: support for timing out other queriers from mrouted
- Hopefully fix issue #22: Crash in (S,G) state when neighbor is lost
- Misc. bug fixes thanks to Coverity Scan, static code analysis tool
  <https://scan.coverity.com/projects/3319>


[v2.1.8][] - 2011-10-22
-----------------------

### Changes
- Update docs of static Rendez-Vous Point, `rp_address`, configuration
  in man page and example `pimd.conf`.  Thanks to Andriy Senkovych
  <andriysenkovych@gmail.com> and YAMAMOTO Shigeru <shigeru@iij.ad.jp>
- Replaced `malloc()` with `calloc()` to mitigate risk of accessing junk
  data and ease debugging, by YAMAMOTO Shigeru <shigeru@iij.ad.jp>
- Extend .conf file `rp_address` option with `priority` field.  Code
  changes and doc updates by YAMAMOTO Shigeru <shigeru@iij.ad.jp>

### Fixes
- A serious bug in `pim_proto.c:receive_pim_register()` was found and
  fixed by Jean-Pascal Billaud.  In essence, the RP check was broken
  since the code only looked at `my_cand_rp_address`, which is not set
  when using the `rp_address` config.  Everything works fine with
  auto-RP mode though.  This issue completely breaks the register path
  since the JOIN(S,G) is never sent back ...
- Fix FTBFS issues reported from Debian.  Later GCC versions trigger
  unused variable warnings.  Fixes by Antonin Kral <a.kral@bobek.cz>


[v2.1.7][] - 2011-01-09
-----------------------

### Changes
- The previous move of runtime dump files to `/var/lib/misc` have been
  changed to `/var/run/pimd` instead.  This to accomodate *BSD systems
  that do not have the `/var/lib` tree, and also recommended in the
  Filesystem Hierarchy Standard:

  <http://www.pathname.com/fhs/pub/fhs-2.3.html#VARRUNRUNTIMEVARIABLEDATA>


[v2.1.6][] - 2011-01-08
-----------------------

### Changes
- Debian package now conflicts with `smcroute`, in addition to `mrouted`.
  It is only possible to run one multicast routing daemon at a time, kernel
  limitation.
- The location of the dump file(s) have been moved from `/var/tmp` to
  `/var/lib/misc` due to the insecure nature of `/var/tmp`.  See more
  below.

### Fixes
- `kern.c:k_del_vif()`: Fix build error on GNU/kFreeBSD
- CVE-2011-0007: Insecure file creation in `/var/tmp`. "On USR1, pimd
  will write to `/var/tmp/pimd.dump` a dump of the multicast route
  table.  Since `/var/tmp` is writable by any user, a user can create a
  symlink to any file he wants to destroy with the content of the
  multicast routing table."


[v2.1.5][] - 2010-11-21
-----------------------

### Changes
- Improved error messages in kern.c
- Renamed CHANGES to ChangeLog

### Fixes
- Import mrouted fix: on GNU/Linux systems (only!) the call to
  `kern.c:k_del_vif()` fails with: `setsockopt MRT_DEL_VIF on vif 3:
  Invalid argument`.  This is due to differences in the Linux and *BSD
  `MRT_DEL_VIF` API.  The Linux kernel expects to receive a `struct
  vifctl` associated with the VIF to be deleted, *BSD systems on the
  other hand expect to receive the index of that VIF.

  Bug reported and fixed on mrouted by Dan Kruchinin <dkruchinin@acm.org>


[v2.1.4][] - 2010-09-25
-----------------------

### Changes
- Support Debian GNU/kFreeBSD, FreeBSD kernel with GNU userland.

### Fixes
- Lior Dotan <liodot@gmail.com> reports that pimd 2.1.2 and 2.1.3 are
  severely broken w.r.t.  uninformed systematic replace of `bcopy()`
  with `memcpy()` API.


[v2.1.3][] - 2010-09-08
-----------------------

### Changes
- `debug.c:syslog()`: Removed GNU:ism %m, use `strerror(errno)` instead.
- Cleanup and ansification of: rp.c, mrt.c, vif.c, route.c
- Initialize stack variables to silence overzealous GCC on PowerPC and
  S/390. Debian bug 595584, this closes pimd issue #3 on GitHub.

### Fixes
- Bug fix for static-rp configurations from Kame's pim6sd route.c r1.28
- Close TODO, merge in relevant changes from Kame's pim6sd `vif.c r1.3`
- Tried fixing `debug.c:logit()` build failure on Sparc due to mixup
  in headers for `tv_usec` type.


[v2.1.2][] - 2010-09-04
-----------------------

### Changes
- License change on mrouted code from OpenBSD team => pimd fully free
  under the simlified 3-clause BSD license!  This was also covered in
  v2.1.0-alpha29.17, but now all files have been updated, including
  LICENSE.mrouted.
- Code cleanup and ansification.
- Simplify Makefile so it works seamlessly on GNU Make and BSD PMake.
- Replaced `bzero()` and `bcopy()` with `memset()` and `memcpy()`.
- Use `getopt_long()` for argument parsing.
- Add, and improve, `-h,--help` output.
- Add `-f,--foreground` option.
- Add `-v,--version` option.
- Add `-l,--reload-config` which sends SIGHUP to a running daemon.
- Add `-r,--show-routes` which sends SIGUSR1 to a running daemon.
- Add `-q,--quit-daemon` which sends SIGTERM to a running daemon.
- Enable calling pimd as a regular user, for `--help` and `--version`.
- Man page cleaned up, a lot, and updated with new options.

### Fixes
- Replaced dangerous string functions with `snprintf()` and `strlcpy()`
- Added checks for `malloc()` return values, all over the code base.
- Fixed issues reported by Sparse (CC=cgcc).
- Retry syscalls `recvfrom()` and `sendto()` on signal (SIGINT).
- Fix build issues on OpenBSD 4.7 and FreeBSD 8.1, Guillaume Sellier.
- Kernel include issues on Ubuntu 8.04, Linux <= 2.6.25, Nikola Knežević
- Fix build issues on NetBSD


[v2.1.1][] - 2010-01-17
-----------------------

Merged all patches from <http://lintrack.org>.

### Changes
- Bumping version again to celebrate the changes and make it easier
  for distributions to handle the upgrade.
- `002-better-rp_address.diff`: Support multicast group address in
  static Rendez-Vous Point .conf option.
- `004-disableall.diff`: Add -N option to pimd.
- `005-vifenable.diff`: Add enable keyword to phyint .conf option.

### Fixes
- `001-debian-6.diff`: Already merged, no-op - only documenting in case
  anyone wonders about it.
- `003-ltfixes.diff`: Various bug fixes and error handling improvements.
- `006-dot19.diff`: The lost alpha29.18 and alpha29.19 fixes by Pavlin
  Radoslavov.


[v2.1.0][] - 2010-01-16
-----------------------

First release from new home at GitHub and by new maintainer.

### Changes
- Integrated the Debian patches from `pimd_2.1.0-alpha29.17-9.diff.gz`
- Fixed the new file include/linux/netinet/in-my.h (Debian) so that the
  #else fallback uses the system netinet/in.h, which seems to work now.
- Bumped version number, this code has been available for a while now.


v2.1.0-alpha29.19 - 2005-01-14
------------------------------

### Fixes
- Don't ignore PIM Null Register messages if the IP version of the inner
  header is not valid.
- Add a missing bracket inside rsrr.c (a bug report and a fix by
  <seyon@oullim.co.kr>)


v2.1.0-alpha29.18 - 2003-05-21
------------------------------

### Changes
- Compilation fix for Solaris 8. Though, no guarantee pimd still works
  on that platform.
- Define `BYTE_ORDER` if missing.
- Update include/netinet/pim.h file with its lastest version
- Update the copyright message of `include/netinet/pim_var.h`


v2.1.0-alpha29.17 - 2003-03-20
------------------------------

### Changes
- The mrouted license, LICENSE.mrouted, updated with BSD-like license!!
  Thanks to the OpenBSD folks for the 2 years of hard work to make this
  happen:

  <http://www.openbsd.org/cgi-bin/cvsweb/src/usr.sbin/mrouted/LICENSE>

- Moved the pimd contact email address upfront in README. Let me repeat
  that here: If you have any questions, suggestions, bug reports, etc.,
  do NOT send them to the PIM IETF Working Group mailing list! Instead,
  use the contact email address specified in README.


v2.1.0-alpha29.16 - 2003-02-18
------------------------------

### Fixes
-   Compilation bugfix for Linux. Bug report by Serdar Uezuemcue
    <serdar@eikon.tum.de>


v2.1.0-alpha29.15 - 2003-02-12
------------------------------

### Fixes
- Routing socket descriptor leak. Bug report and fix by SUZUKI Shinsuke
  <suz@crl.hitachi.co.jp>, incorporated back from pim6sd.
- PIM join does not go upstream. Bug report and fix by SUZUKI Shinsuke
  <suz@crl.hitachi.co.jp>, incorporated back from pim6sd.

``` {.example}
[problem]
PIM join does not go upstream in the following topology, because oif-list
is NULL after subtracting iif from oif-list.

    receiver---rtr1---|
               rtr2---|---rtr3----sender

            rtr1's nexthop to sender = rtr2
            rtr2's nexthop to sender = rtr3

[reason]
Owing to a difference between RFC2362 and the new pim-sm draft.
[solution]
Prunes iif from oiflist when installing it into kernel, instead of
PIM route calculation time.
```


v2.1.0-alpha29.14 - 2003-02-10
------------------------------

### Fixes
- Bugfix in calculating the netmask for POINTOPOINT interface in
  config.c. Bug report by J.W. (Bill) Atwood <bill@cs.concordia.ca>
- `rp.c:rp_grp_match()`: SERIOUS bugfix in calculating the RP per
  group when there are a number of group prefixes in the Cand-RP set.
  Bug report by Eva Pless <eva.pless@imk.fraunhofer.de>


v2.1.0-alpha29.13 - 2002-11-07
------------------------------

### Fixes
- Bugfix in rp.c `bootstrap_initial_delay()` in calculating BSR
  election delay. Fix by SAKAI Hiroaki <sakai.hiroaki@finet.fujitsu.com>


v2.1.0-alpha29.12 - 2002-10-26
------------------------------

### Fixes
- Increase size of send buffers in the kernel.  Bug report by Andrea
  Gambirasio <andrea.gambirasio@softsolutions.it>


v2.1.0-alpha29.11 - 2002-07-08
------------------------------

### Fixes
Bug reports and fixes by SAKAI Hiroaki <sakai.hiroaki@finet.fujitsu.com>

- `init_routesock()`: Bugfix: initializing a forgotten variable. The
  particular code related to that variable is commented-out by default,
  but a bug is a bug.
- `main.c:restart()`: Bugfix: close the `udp_socket` only when it is
  is different from `igmp_socket`.
- `main.c:main()`: if SIGHUP signal is received, reconstruct readers
  and nfds
- Three serious bug fixes thanks to Jiahao Wang <jiahaow@yahoo.com.cn>
  and Bo Cheng <bobobocheng@hotmail.com>:
  - `pim_proto.c:receive_pim_join_prune()`: two bugfixes related to
    the processing of `(*,*,RP)`
  - `pim_proto.c:add_jp_entry()`: Bugfix regarding adding prune
    entries
- Remove the FTP URL from the various README files, and replace it
  with an HTTP URL, because the FTP server on catarina.usc.edu is not
  operational anymore.


v2.1.0-alpha29.10 - 2002-04-26
------------------------------

### Fixes
- Widen space for "Subnet" addresses printed in "Virtual Interface Table"
- Added (commented-out code) to enable different interfaces to belong
  to overlapping subnets. See around line 200 in config.c
- Bugfix in handling of Join/Prune messages when there is one join and one
  prune for the same group. Thanks to Xiaofeng Liu <liu_xiao_feng@yahoo.com>


v2.1.0-alpha29.9 - 2001-11-13
-----------------------------

### Changes

First three entries contributed by Hiroyuki Komatsu <komatsu@taiyaki.org>

- Print line number if there is conf file error.
- If there is an error in the conf file, pimd won't start.
- GRE configuration examples added to README.config.
- New file README.debug (still very short though).

### Fixes
- Increase the config line buffer size to 1024. Bug fix by Hiroyuki
  Komatsu <komatsu@taiyaki.org>


v2.1.0-alpha29.8 - 2001-10-16
-----------------------------

### Changes
- Better log messages for point-to-point links in config.c. Thanks to
  Hitoshi Asaeda <asaeda@yamato.ibm.com>


v2.1.0-alpha29.7 - 2001-10-10
-----------------------------

### Changes
- Added `phyint altnet` (see pimd.conf for usage) for allowing some
  senders look like directly connected to a local subnet. Implemented by
  Marian Stagarescu <marian@bile.cidera.com>
- Added `phyint scoped` (see pimd.conf for usage) for administratively
  disabling the forwarding of multicast groups.  Implemented by Marian
  Stagarescu <marian@bile.cidera.com>
- The License has changed from the original USC to the more familiar
  BSD-like (the KAME+OpenBSD guys brought to my attention that the
  original working in the USC license "...and without fee..." is
  ambiguous and makes it sound that noone can distribute pimd as part of
  some other software distribution and charge for that distribution.
- RSRR disabled by default in Makefile

### Fixes
- Memory leaks bugs fixed in rp.c, thanks to Sri V <vallepal@yahoo.com>
- Compilation problems for RedHat-7.1 fixed. Bug report by Philip Ho
  <cbho@ie.cuhk.edu.hk>
- PID computation fixed (it should be recomputed after a child
  `fork()`).  Thanks to Marian Stagarescu <marian@bile.cidera.com>
- `find_route()`-related bug fixes (always explicitly check for NULL
  return). Bug report by Marian Stagarescu <marian@bile.cidera.com>
- Bug fix re. adding a local member with older Ciscos in `add_leaf()`.
  Bug report by Marian Stagarescu <marian@bile.cidera.com>
- Added explicit check whether `BYTE_ORDER` in pimd.h is defined. Bug
  report by <mistkhan@indiatimes.com>


v2.1.0-alpha29.6 - 2001-05-04
-----------------------------

### Fixes
- Bug fixes in processing Join/Prune messages.  Thanks to Sri V 
 <vallepal@yahoo.com>


v2.1.0-alpha29.5 - 2001-02-22
-----------------------------

### Changes
- `VIFM_FORWARDER()` macro renamed to `VIFM_LASTHOP_ROUTER`.
- Mini-FAQ entries added to README.

### Fixes
- When there is a new member, `add_leaf()` is called by IGMP code for
  any router, not only for a DR.  The reason is because not only the DR
  must know about local members, but the last-hop router as well (so
  eventually it will initiate a SPT switch). Similar fixes to
  `add_leaf()` inside route.c as well. Problem reported by Hitoshi
  Asaeda <asaeda@yamato.ibm.com>. XXX: Note the lenghty comment in the
  beginning of `add_leaf()` about a pimd desing problem that may result
  in SPT switch not initiated immediately by the last-hop router.
- DR entry timer bug fix in timer.c: When `(*,G)`'s iif and (S,G)'s iif
  are not same, (S,G)'s timer for the DR doesn't increase.  Reported
  indirectly by <toshiaki.nakatsu@fujixerox.co.jp>


v2.1.0-alpha29.4 - 2000-12-01
-----------------------------

### Changes
- README cleanup + Mini-FAQ added
- `igmp_proto.c`: printf argument cleanup (courtesy KAME)
- `main.c:restart()`: forgotten printf argument added (courtesy KAME)

### Fixes
- `kern.c:k_stop_pim()`: Fix the ordering of `MRT_PIM` and `MRT_DONE`,
  thanks to Hitoshi Asaeda <asaeda@yamato.ibm.co.jp>
- `route.c:add_leaf()`: mrtentry creation logic bug fix. If the router
  is not a DR, a mrtentry is never created. Tanks to Hitoshi Asaeda
  <asaeda@yamato.ibm.co.jp> & (indirectly) <toshiaki.nakatsu@fujixerox.co.jp>
- `pim_proto.c`: Two critical bug fixes. J/P prune suppression related
  message and J/P message with `(*,*,RP)` entry inside. Thanks to
  Azzurra Pantella <s198804@studenti.ing.unipi.it> and Nicola Dicosmo
  from University of Pisa
- `pim_proto.c:receive_pim_bootstrap()`: BSR-related fix from Kame's
  pim6sd.  Even when the BSR changes, just schedule an immediate
  advertisemnet of C-RP-ADV, instead of sending message, in order to
  avoid sending the advertisement to the old BSR.  In response to comment
  from <toshiaki.nakatsu@fujixerox.co.jp>


v2.1.0-alpha29.3 - 2000-10-13
-----------------------------

### Fixes
- `ADVANCE()` bug fix in routesock.c (if your system doesn't have
  `SA_LEN`) thanks to Eric S. Johnson <esj@cs.fiu.edu>


v2.1.0-alpha29.2 - 2000-10-13
-----------------------------

NB: THIS pimd VERSION WON'T WORK WITH OLDER PIM-SM KERNEL PATCHES
(kernel patches released prior to this version)!

### Changes
- The daemon that the kernel will prepare completely the inner multicast
  packet for PIM register messages that the kernel is supposed to
  encapsulate and send to the RP.
- Now pimd compiles on OpenBSD-2.7. PIM control messages exchange test
  passed.  Don't have the infrastructure to perform more complete testing.
- `main.c:cleanup()`: Send `PIM_HELLO` with holdtime of '0' if pimd
  is going away, thanks to JINMEI Tatuya <jinmei@isl.rdc.toshiba.co.jp>
- `include/netinet/pim.h` updated
- pimd code adapted to the new `struct pim` definition.
- Added `PIM_OLD_KERNEL` and `BROKEN_CISCO_CHECKSUM` entries in the
  Makefile.
- Don't ignore kernel signals if any of src or dst are NULL.
- Don't touch `ip_id` on a PIM register message
- README cleanup: kernel patches location, obsolete systems clarification, etc.
- `k_stop_pim()` added to `cleanup()` in `main.c` (courtesy Kame)

### Fixes
- `RANDOM()` related bug fix re. `jp_value` calculation in `pim_proto.c`,
  thanks to JINMEI Tatuya <jinmei@isl.rdc.toshiba.co.jp>
- `realloc()` related memory leak bug in `config_vifs_from_kernel()`
  in config.c courtesy Kame's pim6sd code.
- Solaris-8 fixes thanks to Eric S. Johnson <esj@cs.fiu.edu>
- `BROKEN_CISCO_CHECKSUM` bug fix thanks to Eric S. Johnson
  <esj@cs.fiu.edu> and Hitoshi Asaeda.
- `main.c`: 1000000 usec -> 1 sec 0 usec.  Fix courtesy of the Kame Project
- `main.c:restart()` fixup courtesy of the Kame Project
- various min. message length check for the received control messages
  courtesy of the Kame project. XXX: the pimd check is not enough!
- VIF name string comparison fix in `routesock.c:getmsg()`, courtesy
  of the Kame project
- Missing brackets added inside `age_routes()`, shows up only if
  `KERNEL_MFC_WC_G` is defined, courtesy of the Kame Project


v2.1.0-alpha28 - 2000-05-15
---------------------------

### Changes
- added #ifdef `BROKEN_CISCO_CHECKSUM` (disabled by default) to make
  cisco RPs happy (read the comments in pim.c)
- added #ifdef `PIM_TYPEVERS_DECL` in netinet/pim.h as a workaround that
  ANSI-C doesn't guarantee that bit-fields are tightly packed together
  (although all modern C compilers should not create a problem).

### Fixes
- Fixes to enable point-to-point interfaces being added correctly,
  thanks to Roger Venning <Roger.Venning@corpmail.telstra.com.au>
- A number of minor bug fixes


v2.1.0-alpha27 - 2000-01-21
---------------------------

NB: this release may the the last one from 2.1.0.  The next release will
be 2.2.0 and there will be lots of changes inside.

### Fixes
- Bug fix in `rp.c:add_grp_mask()` and `rp.c:delete_grp_mask()`: in
  some cases if the RPs are configured with nested multicast prefixes,
  the add/delete may fail.  Thanks to Hitoshi Asaeda and the KAME team
  for pointing out this one.


v2.1.0-alpha26 - 1999-10-29
---------------------------

### Fixes

-   Bug fix in `receive_pim_register()` in `pim_proto.c:ntohl()` was
    missing inside `IN_MULTICAST()`. Thanks to Fred Griffoul
    <griffoul@ccrle.nec.de>

-   Bug report and fix by Hitoshi Asaeda <asaeda@yamato.ibm.co.jp> in
    `pim_proto.c:receive_pim_cand_rp_adv()` (if a router is not a BSR).
    Another bug in `rp.c:delete_grp_mask_entry()`: an entry not in the
    head of the list was not deleted propertly.

-   Some `VIFF_TUNNEL` checks added or deleted in various places. Slowly
    preparing pimd to be able to work with GRE tunnels...


v2.1.0-alpha25 - 1999-08-30
---------------------------

Bug reports and fixes by Hitoshi Asaeda <asaeda@yamato.ibm.co.jp> inside
`parse_reg_threshold()` and `parse_data_threshold()` in config.c

### Changes
- Successfully added multicast prefixes configured in pimd.conf are
  displayed at startup
- Use `include/freebsd` as FreeBSD-3.x include files and
  `include/freebsd2` for FreeBSD-2.x.

### Fixes
- Test is performed whether a `PIM_REGISTER` has invalid source and/or
  group address of the internal packet.


v2.1.0-alpha24 - 1999-08-09
---------------------------

### Changes
- `PIM_DEFAULT_CAND_RP_ADV_PERIOD` definition set to 60, but default
  time value for inter Cand-RP messages is set in pimd.conf to 30 sec.
- `PIM_REGISTER` checksum verification in `receive_pim_register()`
  relaxed for compatibility with some older routers. The checksum has
  to be computed only over the first 8 bytes of the PIM Register (i.e.
  only over the header), but some older routers might compute it over
  the whole packet. Hence, the checksum verification is over the first
  8 bytes first, and if if it fails, then over the whole packet. Thus,
  pimd that is RP should still work with older routers that act as DR,
  but if an older router is the RP, then pimd cannot be the DR. Sorry,
  don't know which particular routers and models create the checksum
  over the whole PIM Register (if there are still any left).


v2.1.0-alpha23 - 1999-05-24
---------------------------

### Changes
- Finally pimd works under Linux (probably 2.1.126, 2.2.x and 2.3.x).
  However, a small fix in the kernel `linux/net/ipv4/ipmr.c` is
  necessary. In function `pim_rcv()`, remove the call to
  `ip_compute_csum()`:

``` {.c}
--- linux/net/ipv4/ipmr.c.org   Thu Mar 25 09:23:34 1999
+++ linux/net/ipv4/ipmr.c       Mon May 24 15:42:45 1999
@@ -1342,8 +1342,7 @@
         if (len < sizeof(*pim) + sizeof(*encap) ||
            pim->type != ((PIM_VERSION<<4)|(PIM_REGISTER)) ||
            (pim->flags&PIM_NULL_REGISTER) ||
-           reg_dev == NULL ||
-           ip_compute_csum((void *)pim, len)) {
+           reg_dev == NULL) {
                kfree_skb(skb);
                 return -EINVAL;
         }
```

- in pimd.conf `phyint` can be specified not only by IP address, but
  by name too (e.g. `phyint de1 disable`)
- in pimd.conf `preference` and `metric` can be specified per `phyint`
  Note that these `preference` and `metric` are like per iif.
- `MRT_PIM` used (again) instead of `MRT_ASSERT` in kern.c.  The problem
  is that Linux has both `MRT_ASSERT` and `MRT_PIM`, while *BSD has only
  `MRT_ASSERT`.

``` {.c}
#ifndef MRT_PIM
#define MRT_PIM MRT_ASSERT
#endif
```

- Rely on `__bsdi__`, which is defined by the OS, instead of `-DBSDI` in
  Makefile, change by Hitoshi Asaeda.  Similarly, use `__FreeBSD__`
  instead of `-DFreeBSD`
- Linux patches by Fred Griffoul <griffoul@ccrle.nec.de> including a
  `netlink.c` instead of `routesock.c`
- `vif.c:zero_vif()`: New function

### Fixes
All bug reports thanks to Kaifu Wu <kaifu@3com.com>

- Linux-related bug fixes regarding raw IP packets byte ordering
- Join/Prune message bug fixed if the message contains several groups
  joined/pruned


v2.1.0-alpha22 - 1998-11-11
---------------------------

Bug reports by Jonathan Day <jd9812@my-dejanews.com>

### Fixes
- Bug fixes to compile under newer Linux kernel (linux-2.1.127) To
  compile for older kernels (ver < ???), add `-Dold_Linux` to the
  Makefile
- For convenience, the `include/linux/netinet/{in.h,mroute.h}` files
  are added, with few modifications applied.


v2.1.0-alpha21 - 1998-11-04
---------------------------

### Fixes
- `pim_proto.c:join_or_prune()`: Bug fixes in case of (S,G) overlapping
  with `(*,G)`. Bug report by Dirk Ooms <Dirk.Ooms@alcatel.be>
- `route.c:change_interfaces()`: Join/Prune `(*,G)`, `(*,*,RP)` fire
  timer optimization/fix.


v2.1.0-alpha20 - 1998-08-26
---------------------------

### Changes
- (Almost) all timers manipulation now use macros
- `pim.h` and `pim_var.h` are in separate common directory
- Added BSDI definition to `pim_var.h`, thanks to Hitoshi Asaeda.

### Fixes
- fix TIMEOUT definitions in difs.h (bug report by Nidhi Bhaskar)
  (originally, if timer value less than 5 seconds, it won't become 0)
  It is HIGHLY recommended to apply that fix, so here it is:

``` {.c}
-------------BEGIN BUG FIX-------------------
  1) Add the following lines to defs.h (after #define FALSE):

#ifndef MAX
#define MAX(a,b) (((a) >= (b))? (a) : (b))
#define MIN(a,b) (((a) <= (b))? (a) : (b))
#endif /* MAX & MIN */

  2) Change the listed below TIMEOUT macros to:

#define IF_TIMEOUT(timer)      \
    if (!((timer) -= (MIN(timer, TIMER_INTERVAL))))

#define IF_NOT_TIMEOUT(timer)      \
    if ((timer) -= (MIN(timer, TIMER_INTERVAL)))

#define TIMEOUT(timer)         \
    (!((timer) -= (MIN(timer, TIMER_INTERVAL))))

#define NOT_TIMEOUT(timer)     \
    ((timer) -= (MIN(timer, TIMER_INTERVAL)))
---------------END BUG FIX-------
```


v2.1.0-alpha19 - 1998-06-29
---------------------------

Both bug reports by Chirayu Shah <shahzad@torrentnet.com>

### Fixes
- bug fix in `find_route()` when searching for `(*,*,RP)`
- bug fix in `move_kernel_cache()`: no need to do `move_kernel_cache()`
  from `(*,*,R)` to `(*,G)` first when we call `move_kernel_cache()` for
  (S,G)


v2.1.0-alpha18 - 1998-05-29
---------------------------

### Changes
- Now compiles under Linux (haven't checked whether the PIMv2 kernel
  support in linux-2.1.103 works)

### Fixes
- `parse_default_source*()` bug fix (bug reports by Nidhi Bhaskar)
- allpimrouters deleted from igmp.c (already defined in pim.c)
- igmpmsg defined for IRIX


v2.1.0-alpha17 - 1998-05-21
---------------------------

### Changes
- `(*,G)` MFC kernel support completed and verified. Compile with
  `KERNEL_MFC_WC_G` defined in Makefile, but then must use it only
  with a kernel that supports `(*,G)`, e.g. `pimkern-PATCH_7`.
  Currently, kernel patches available for FreeBSD and SunOS only.

### Fixes
- `MRTF_MFC_CLONE_SG` flag set after `delete_single_kernel_cache()` is
  called


v2.1.0-alpha16 - 1998-05-19
---------------------------

### Changes
- PIM registers kernel encapsulation support. Build with
  `PIM_REG_KERNEL_ENCAP` defined in Makefile.
- `(*,G)` MFC support. Build with `KERNEL_MFC_WC_G` defined in
  Makefile. However, `MFC_WC_G` is still not supported with
  `pimkern-PATCH_6`, must disable it for now.
- `mrt.c:delete_single_kernel_cache_addr()`: New function, uses
  source, group to specify an MFC to be deleted


v2.1.0-alpha15 - 1998-05-14
---------------------------

- Another few bug fixes related to NetBSD definitions thanks to Heiko
  W.Rupp <hwr@pilhuhn.de>


v2.1.0-alpha14 - 1998-05-12
---------------------------

- A few bug fixes related to NetBSD definitions thanks to Heiko W.Rupp
  <hwr@pilhuhn.de>


v2.1.0-alpha13 - 1998-05-11
---------------------------

### Changes
- If the RP changes, the necessary actions are taken to pass the new RP
  address to the kernel.  To be used for kernel register encap support.
  Wnat needs to be done is: (a) add `rp_addr` entry to the mfcctl
  structure, and then just set it in `kern.c:k_chf_mfc()`.  Obviously,
  the kernel needs to support the register encapsulation (instead of
  sending WHOLEPKT to the user level).  In the near few days will make
  the necessary kernel changes.
- `change_interfaces()`: Added "flags" argument. The only valid flag
  is `MFC_UPDATE_FORCE`, used for forcing kernel call when only the RP
  changes.
- `k_chg_mfc()` has a new argument: rp~addr~. To be used for kernel
  register encapsulation support
- `MRT_PIM` completely replaced by `MRT_ASSERT`
- `move_kernel_cache()`: Argument `MFC_MOVE_FORCE` is a flag instead
  of TRUE/FALSE
- `process_cache_miss()`: removed unneeded piece of code


v2.1.0-alpha12 - 1998-05-10
---------------------------

### Changes
- Use the cleaned up `netinet/pim.h`
- Remove the no needed anymore pim header definition in `pimd.h`
- Don't use `MRT_PIM` in in kern.c anymore, replaced back with
  `MRT_ASSERT`.
- `added default_source_metric` and `default_source_preference` (1024)
  because the kernel's unicast routing table is not a good source of
  info; configurable in pimd.conf
- Can now compile under NetBSD-1.3, thanks to Heiko W.Rupp <hwr@pilhuhn.de>

### Fixes
- Incorrect setup of the borderBit and nullRegisterBit (different for
  big and little endian machines) fixed; `*_BORDER_BIT` and
  `*NULL_REGISTER_BIT` redefined
- don't send `pim_assert` on tunnels or register vifs (if for whatever
  reason we receive on such interface)
- ignore `WRONGVIF` messages for register and tunnel vifs (the cleaned
  up kernel mods dont send such signal, but the older (before May 9 '98)
  pimd mods that signaling was enabled


v2.1.0-alpha11 - 1998-03-16
---------------------------

### Changes
- `vif.c:find_vif_direct_local()`: New function, used in `routesock.c`,
  `igmp_proto.c`
- Use `MFC_MOVE_FORCE/MFC_MOVE_DONT_FORCE` flag in `mrt.c`, `route.c`,
  `pim_proto.c`, when need to move the kernel cache entries between
  `(*,*,RP)`, `(*,G)`, `(S,G)`
- new timer related macros: `SET_TIMER()`, `FIRE_TIMER()`,
  `IF_TIMER_SET()`, `IF_TIMER_NOT_SET()`

### Fixes
- `timer.c:age_routes()`: bunch of fixes regarding J/P message
  fragmentation
- `route.c:process_wrong_iif()`: (S,G) SPT switch bug fix: ANDed
  `MRTF_RP` fixed to `MRTF_RP`
- `pim_proto.c` & `timer.c`: (S,G) Prune now is sent toward RP, when
  iif toward S and iif toward RP are different
- `pim_proto.c:join_or_prune()` bug fixes
- `pim_proto.c`: (S,G) Prune entry's timer now set to J/P message
  holdtime
- `pim_proto.c:receive_pim_join_prune()`: Ensure pruned interfaces are
  correctly reestablished
- `timer.c:age_routes()`: now (S,G) entry with local members
  (inherited from `(*,G)`) is timeout propertly
- `timer.c:age_routes()`: (S,G) J/P timer restarted propertly
- `timer.c:age_routes()`: check also the (S,G)RPbit entries in the
  forwarders and RP and eventually switch to the shortest path if data
  rate too high
- `route.c:process_wrong_vif()` fire J/P timer
- `route.c:switch_shortest_path()`: reset the iif toward S if there is
  already (S,G)RPbit entry


v2.1.0-alpha10 - 1998-03-03
---------------------------

Temp. non-public release.

### Changes
- `interval` can be applied for data rate check. The statement in
  `pimd.conf` that only the default value will be used is not true
  anymore.
- The RP-initiated and the forwarder-initiated (S,G) switch threshold
  rate can be different.
- `pim_proto.c:receive_pim_register()`: check if I am the RP for that
  group, and if "no", send `PIM_REGISTER_STOP` (XXX: not in the
  spec, but should be!)
- `pim_proto.c:receive_pim_register_stop()`: check if the
  `PIM_REGISTER_STOP` originator is really the RP, before suppressing
  the sending of the PIM registers. (XXX: not in the spec but should
  be there)
- `rp.c:check_mrtentry_rp()`: new function added to check whether the
  RP address is the corresponding one for the given mrtentry
- `debug.c:dump_mrt()` timer values added
- `route.c`: `add_leaf()`, `process_cache_miss()`,
  `process_wrong_iif()` no routing entries created for the LAN scoped
  addresses
- `DEBUG_DVMRP_DETAIL` and `DEBUG_PIM_DETAIL` added

### Fixes
- `mrt.c:add_kernel_cache()`: no kernel cache duplicates
- `mrt.c:move_kernel_cache()`: if the iif of the `(*,*,R)` (or `(*,G)`)
  and (S,G) are different, dont move the cache entry "UP"
- `timer.c:age_routes()`: (S,G) `add_jp_entry()` flag fixed, SPT
  switch related.
- `kern.c:k_get_sg_cnt()`: modified to compensate for the kernel's
  return code bug for getting (S,G) byte count (`SIOCGETSGCNT`)
- `pim_proto.c:receive_pim_register()`: if the (S,G) oif is NULL, now
  checks whether the iif is `register_vif`


v2.1.0-alpha9 - 1998-02-18
--------------------------

### Changes
- "non-commersial" statement deleted from the copyright message
- mrinfo support added
- mtrace support added (not completed and not enough tested)
- if invalid local address for `cand_rp` or `cand_bootstrap_router` in
  `pimd.conf`, automatically will use the largest local multicast
  enabled address
- include directory for FreeBSD and SunOS added, so now pimd can be
  compiled without having the necesary include files added to your
  system. Probably a bad idea and may remove it later.
- Fixed some default values for the IP header of IGMP and PIM packets
- `VIFF_PIM_NBR` and `VIFF_DVMRP_NBR` flags added
- `VIFF_REGISTER` now included in the RSRR vifs report
- `find_route()` debug messages removed
- #ifdef for `HAVE_SA_LEN` corrected
- `debug.c`: small fixes


v2.1.0-alpha8 - 1997-11-23
--------------------------

### Fixes
- BSDI related bug fix in defs.h
- small changes in Makefile


v2.1.0-alpha7 - 1997-11-23
--------------------------

### Changes
- RSRR support for `(*,G)` completed
- BSDI 3.0/3.1 support by Hitoshi Asaeda <asaeda@yamato.ibm.co.jp>
  (the kernel patches will be available soon)
- Improved debug messages format, thanks to Hitoshi Asaeda
- A new function `netname()` for network IP address print instead of
  `inet_fmts()`, thanks to Hitoshi Asaeda.
- `pimd.conf`: format changed


v2.1.0-alpha6 - 1997-11-20
--------------------------

### Fixes
- Remove inherited leaves from (S,G) when a receiver drops membership
- some parameters when calling `change_interface()` fixed
- Use `send_pim_null_register` + take the appropriate action when the
  register suppression timer expires
- bug fix related to choosing the largest local IP address for little
  endian machines.


v2.1.0-alpha5
-------------

### Fixes
- `main.c:main()`: startup message fix
- `timer.c:age_routes()`: bug fix in debug code


v2.1.0-alpha4 - 1997-10-31
--------------------------

### Changes
- Minor changes, so pimd now compiles for SunOS 4.1.3 (cc, gcc)

### Fixes
- `pim_proto.c:send_periodic_pim_join_prune()`: bug fix thanks to SunOS
  cc warning(!), only affects the `(*,*,RP)` stuff.
- `pimd.conf`: two errors, related to the rate limit fixed


v2.1.0-alpha3 - 1997-10-13
--------------------------

### Changes
- `Makefile`: cleanup
- `defs.h`: cleanup
- `routesock.c`: cleanup

### Fixes
- `igmp_proto.c:accept_group_report()`: bug fixes
- `pim_proto.c:receive_pim_hello()`: bug fixes
  `route.c:change_interfaces()`: bug fixes
- `rp.c`: bug fixes in `init_rp_and_bsr()`, `add_cand_rp()`, and
  `create_pim_bootstrap_message()`


v2.1.0-alpha2 - 1997-09-23
--------------------------

### Changes
- `Makefile`: "make diff" code added
- `debug.c`: debug output slightly changed

### Fixes
- `defs.h:*TIMEOUT()`: definitions fixed
- `route.c`: bugs fixed in `change_interface()` and
  `switch_shortest_path()`
- `timer.c:age_routes()`: number of bugs fixed


v2.1.0-alpha1 - 1997-08-26
--------------------------

### Changes

First alpha version of the "new, up to date" pimd.  RSRR and Solaris
support added.  Many functions rewritten and/or modified.

[UNRELEASED]: https://github.com/ocochard/pimd/compare/3.3.0...HEAD
[v3.3.0]:     https://github.com/ocochard/pimd/compare/3.2.0...3.3.0
[v3.2.0]:     https://github.com/ocochard/pimd/compare/3.1.0...3.2.0
[v3.1.0]:     https://github.com/ocochard/pimd/compare/3.0.0...3.1.0
[v3.0.0]:     https://github.com/ocochard/pimd/compare/2.3.2...3.0.0
[v2.3.2]:     https://github.com/troglobit/pimd/compare/2.3.1...2.3.2
[v2.3.1]:     https://github.com/troglobit/pimd/compare/2.3.0...2.3.1
[v2.3.0]:     https://github.com/troglobit/pimd/compare/2.2.1...2.3.0
[v2.2.1]:     https://github.com/troglobit/pimd/compare/2.2.0...2.2.1
[v2.2.0]:     https://github.com/troglobit/pimd/compare/2.1.8...2.2.0
[v2.1.8]:     https://github.com/troglobit/pimd/compare/2.1.7...2.1.8
[v2.1.7]:     https://github.com/troglobit/pimd/compare/2.1.6...2.1.7
[v2.1.6]:     https://github.com/troglobit/pimd/compare/2.1.5...2.1.6
[v2.1.5]:     https://github.com/troglobit/pimd/compare/2.1.4...2.1.5
[v2.1.4]:     https://github.com/troglobit/pimd/compare/2.1.3...2.1.4
[v2.1.3]:     https://github.com/troglobit/pimd/compare/2.1.2...2.1.3
[v2.1.2]:     https://github.com/troglobit/pimd/compare/2.1.1...2.1.2
[v2.1.1]:     https://github.com/troglobit/pimd/compare/2.1.0...2.1.1
[v2.1.0]:     https://github.com/troglobit/pimd/compare/BASE...2.1.0
