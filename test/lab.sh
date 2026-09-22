#!/bin/sh
# PIM-SM regression lab, the same scenarios over FreeBSD vnet jails and
# over Linux network namespaces
#
# Written for the FreeBSD code paths of pimd that no CI covered: the rest
# of this directory is Linux-only, it is built on network namespaces, veth
# pairs and `unshare`, so on FreeBSD none of it can even start.  Everything
# asserted there goes through the kern.c BSD branches, and through
# routesock.c (RPF lookups over the PF_ROUTE socket) rather than netlink.c
# and the Linux ones.  On Linux the same scenarios run against that kernel
# and netlink.c instead, most of them with no counterpart in the automake
# suite.  Not in TESTS on either, see Requires below.
#
# NETLINK=yes runs the very same scenarios against the other RPF backend:
# FreeBSD 13.2 and later answer the same lookups over netlink(4), and a
# pimd built with `configure --enable-netlink` asks them that way.  The two
# are indistinguishable from the outside, which is the point of running
# both, so the knob does not take the tree on trust -- it asks the daemon
# what it was built with before a single assertion runs.
#
# What makes this possible on FreeBSD:
#   - sys/netinet/ip_mroute.c is fully VNET-ized (V_viftable, V_numvifs,
#     V_ip_mrouter, V_multicast_register_if), so each vnet jail owns a
#     private multicast forwarding cache and vif table.
#   - prison_priv_check() grants PRIV_NETINET_MROUTE, PRIV_NETINET_RAW and
#     PRIV_NET_BPF unconditionally to jails with their own network stack
#     (sys/kern/kern_jail.c), so pimd's raw IGMP/PIM sockets and its
#     MRT_INIT setsockopt() work inside a jail with no allow.raw_sockets.
#   - ip_mroute.ko has to be loaded from the host: a jail cannot kldload.
#
# Topology, one vnet jail per box, all links /24:
#
#    ED1            R1             R2             R3            ED2
#  (sender)     (FHR / DR)     (BSR + RP)        (LHR)       (receiver)
#     |              |              |              |              |
#     +--10.0.1.0/24-+-10.0.12.0/24-+-10.0.23.0/24-+--10.0.3.0/24-+
#      .10        .1   .1        .2   .2        .3   .1        .10
#     epair101a/b     epair112a/b    epair123a/b    epair203a/b
#
# The interface and jail names throughout this file are the ones slot 0
# uses; -s N puts N in front of every epair and bridge unit number and
# after the "pimd" of every jail name, see SLOT below.
#
# Unicast routing is static on purpose: a static route carries a metric of
# its own, which `route change -metric` moves and pimd reads back out of
# the kernel for its Asserts, so bird or frr here would only add a
# dependency and a second thing to debug.  The administrative distance
# pimd puts beside that metric does still come from pimd.conf, and no
# routing daemon would change that either -- see M4 in
# doc/rfc7761-compliance.md.  The RP is pinned to R1's side of the R1-R2
# link (10.0.12.2) so the expected RP address is deterministic instead of
# "highest active IP".
#
# Multicast then has to survive the full PIM-SM sequence: ED2's IGMP
# report reaches R3, R3 sends a (*,G) join toward the RP, ED1's first
# packet makes R1 PIM-register-encapsulate to R2, R2 decapsulates and
# forwards down the shared tree, and with spt-threshold set low the
# routers then switch to the shortest path tree.
#
# Twenty-one scenarios are built on that topology.  Most differ only in which
# pimd.conf each router gets and which assertions run; rp-offpath adds one
# link to close the chain into a triangle; the two gif ones add a tunnel and
# take R2 out of PIM entirely; the two shared segment ones rebuild the two
# right hand links as bridged segments and hang two more routers off them;
# alias gives one interface a second address and moves the sender onto it;
# ifnew, ifgone and renumber change a link under a pimd that is already
# running:
#
#   rpt         R2 is BSR and RP, ED2 joins, traffic has to reach it over
#               the shared tree.  Takes about 90s.
#   keepalive   R1 is BSR and RP for its own directly connected source and
#               nobody joins the group, which is the setup of
#               https://github.com/troglobit/pimd/issues/251.  The (S,G)
#               entries then have an empty outgoing interface list, and
#               pimd used to restart the entry timer only for entries that
#               had outgoing interfaces: every source was aged out a few
#               seconds after a cache miss had recreated it, so sources
#               kept appearing and disappearing while they were sending.
#               R1 runs with local-sg-limit set to exactly the number of
#               groups, so the same wait shows entries at the limit being
#               refreshed rather than refused; then a second sender floods
#               more groups, which RFC 7761 sec. 6.4 names first among the
#               attacks on a router's state, and none of them may take a
#               slot, and after a reload the count has to have been given
#               back.  Takes about 6 minutes, it has to outlive
#               PIM_DATA_TIMEOUT (210s).
#   rp-lasthop  R3 is BSR and RP *and* the last hop router for the only
#               receiver, while the source sits behind R1 two hops away,
#               which is the setup of
#               https://github.com/troglobit/pimd/issues/243.  Everybody
#               there reports the same thing over a tunnel: traffic from a
#               source remote to the RP never reaches the receivers that
#               hang off the RP itself, and moving the RP to the other end
#               moves the broken direction with it.  Takes about 2 minutes.
#
#               No other test covers this shape: rp.sh keeps the two roles
#               on separate routers (R2 is RP, R3 is last hop), so the RP
#               there never has a directly connected member and its (*,G)
#               never has the register vif as its incoming interface.
#   rp-offpath  The only scenario whose topology is not a chain: one extra
#               link joins the first hop router to the last hop one, and
#               the RP sits on the third side of the triangle, off the path
#               the traffic takes once the shortest path tree is up.  That
#               is the topology of
#               https://github.com/troglobit/pimd/issues/211.
#
#                                 R2 (BSR + RP, 10.0.23.2)
#                                /      \
#                    10.0.12/24 /        \ 10.0.23/24
#                              /          \
#                 ED1 --- R1 -+------------+- R3 --- ED2
#                  (sender) (FHR) 10.0.13/24 (LHR) (receiver)
#
#               Two things only this shape has.  Every router is adjacent
#               to the RP router, so the last hop router is directly
#               connected to the BSR and to the RP, and R3's RPF interface
#               towards the source is the direct link while its (*,G)
#               arrives over R2, so the switch to the shortest path tree
#               has to move the incoming interface between two ordinary
#               interfaces rather than off the register vif.
#
#               The first is what the issue is about.  k_req_incoming()
#               (src/routesock.c) is the only RPF lookup pimd has on BSD,
#               and it used to go to the kernel even for an address on one
#               of its own subnets; a route to a connected subnet carries
#               no gateway, so the answer came back with no RPF neighbour,
#               and receive_pim_bootstrap() (src/pim_proto.c) drops a
#               Bootstrap whose RPF neighbour is 0.0.0.0.  The router next
#               to the BSR was then the one router in the domain that never
#               learned the RP set, so it could not send the (*,G) Join its
#               receiver needed and nothing was ever forwarded, which is
#               what the issue reports.  The fix, 7aed78f, is in
#               k_req_incoming(): a destination on a connected subnet is
#               answered from the vif table, with the destination as its
#               own RPF neighbour, the way netlink.c has always answered
#               it on Linux.  Takes about 2 minutes.
#   gif-tunnel  rp-lasthop again, but R1 and R3 are joined by a gif tunnel
#               across a plain unicast R2 that runs no pimd at all, which
#               is the shape everyone on #243 actually runs: two PIM
#               routers either side of a VPN, nothing but IP in between.
#
#                 ED1 --- R1 ==== gif0, 172.16.0.0/24 ==== R3 --- ED2
#                          \                              /
#                           +--- R2, unicast only -------+
#
#               What this adds over rp-lasthop is the interface type.  A
#               gif is IFF_POINTOPOINT, so config_vifs_from_kernel() takes
#               the peer from ifa_dstaddr and sets VIFF_POINT_TO_POINT and
#               VIFF_REXMIT_PRUNES (src/config.c), a path no epair in this
#               lab ever reaches.  The inner addresses deliberately carry a
#               /24 rather than a /30 or a bare peer address, because that
#               is what the WireGuard and OpenVPN configs in the issue use:
#               a point-to-point link whose netmask claims a whole subnet.
#               Takes about 2 minutes.
#   gif-tunnel-staticrp
#               gif-tunnel again, but the RP is configured with a static
#               "rp-address" on both ends instead of being elected, which is
#               how every pimd.conf quoted in #243 is written.  That is a
#               different code path, not another way of reaching the same
#               state: my_cand_rp_address is only ever assigned while
#               parsing cand_rp (src/config.c), so with a static RP it stays
#               0.0.0.0 and the router that *is* the RP answers "no" to
#               every internal test of whether it is.  Takes about 3
#               minutes.
#   shared-lan  The only scenario with more than one PIM router on a link.
#               Three PIM routers share one segment, so PIM has to run the
#               elections that a point-to-point link never needs:
#
#                                          .--- R3 ---.
#                                         /            \
#     ED1 --- R1 --- R2 --- br0 ---------+            br1 --+--- R5 --- ED2
#           (FHR)  (BSR/RP)               \            /    |
#                                          '--- R4 ---'     '--- ED3
#
#         10.0.1/24   10.0.12/24   10.0.23/24      10.0.3/24    10.0.5/24
#
#               R3 (10.0.3.2), R4 (10.0.3.3) and R5 (10.0.3.1) all sit on
#               br1, and the addresses put its two elections on different
#               routers: R4 is the PIM DR, because DR election falls back to
#               the highest address (restart_dr_election() in
#               src/pim_proto.c), while R5 is the IGMP querier, because that
#               election takes the lowest one (src/igmp_proto.c).
#
#               An assert needs two routers putting the same stream on one
#               LAN, and here they get there by different routes.  R4
#               forwards because ED3's IGMP report is its leaf: the report
#               reaches every router on the segment, but add_leaf()
#               (src/route.c) looks the group up with DONT_CREATE unless the
#               receiving vif is the DR's, so only the DR ever acts on it.
#               IGMP can therefore hand an oif to R4 and to nobody else, and
#               the second forwarder has to come from PIM: R5 wants the group
#               for ED2 and its RPF neighbour is R3, so its Join names R3 as
#               the upstream router, and receive_pim_join_prune()
#               (src/pim_proto.c) only lets the router named in a Join add
#               the oif - the rest of the LAN uses it for suppression.
#
#               R3 and R4 then both forward onto br1, each sees the other's
#               copy arrive on an interface that is not its iif, the kernel
#               raises IGMPMSG_WRONGVIF for it (ip_mroute.c, with the assert
#               upcalls pimd turns on through MRT_PIM), and the assert that
#               follows moves the loser's oif into asserted_oifs (calc_oifs()
#               in src/route.c).  None of that is reachable in any other
#               scenario here: every other link is an epair with exactly one
#               router at each end.
#
#               The election is also the only one in this file that is not
#               settled by the addresses.  R3 and R4 reach the RP at a
#               metric route_metrics() gives their static route, so step 12
#               can better it on either side and RFC 7761 4.6.3 has to move
#               the LAN to whichever of them is nearer: pimd takes the
#               metric it asserts with from the kernel (rmx_metric through
#               routesock.c), where it used to be a constant out of
#               pimd.conf that no route change could move.  Takes about 5
#               minutes.
#   shared-lan-spt
#               The same LAN and the same two contenders, but R5 is allowed
#               onto the shortest path tree, so R3 ends up with (S,G)
#               forwarding state of its own while R4 still has nothing but
#               ED3's (*,G) leaf.
#
#               That is supposed to decide the assert on its own.  RFC 7761
#               4.6.1 compares assert metrics field by field with
#               rpt_bit_flag first, and my_assert_metric() (p.93) returns
#               the SPT metric, with that flag clear, only when
#               CouldAssert(S,G,I) holds - which requires SPTbit(S,G) ==
#               TRUE (p.75).  R4 has no (S,G) state, so it must assert with
#               the flag set and lose to R3 before either address is looked
#               at.  R3 has the *lower* address, so a router that gets this
#               right and one that falls through to the tiebreak give
#               opposite answers, and the scenario can tell them apart.
#
#               pimd used to get it wrong, and the scenario carried this
#               file's only live xfail() for it: send_pim_assert() and
#               receive_pim_assert() (src/pim_proto.c) both took the RPT
#               bit straight from MRTF_RP on the entry they were
#               forwarding off, and MRTF_RP is only ever set from an
#               explicit (S,G,rpt) Join/Prune or when an entry's iif
#               changes to point at the RP (src/route.c, src/mrt.c) -
#               never on the (S,G) that a cache miss builds underneath a
#               (*,G).  So R4 claimed the shortest path tree it never
#               joined, the metrics tied, and the address handed it a win
#               the spec does not.
#               Fixed in 4cb79f1, which gave both paths one
#               my_assert_metric() deriving the bit from MRTF_SPT, the
#               flag that really is the spec's SPTbit.  Assertion 9
#               reports ok and is kept as a tripwire, its xfail() with it.
#               Takes about 3 minutes.
#   assert-recover
#               The same LAN and the same two contenders once more, and the
#               only scenario about how a router *leaves* the assert state
#               rather than how it enters one.  RFC 7761 sec. 4.6 gives the
#               Loser state four ways out and the Winner state two, and two
#               of those six are reachable nowhere else in this file.
#
#               It starts from shared-lan's answer: R4 holds the LAN, R3 is
#               the loser.  Then R4's pimd is restarted, fast enough that
#               R3 still knows it as a neighbour, so the Hello coming back
#               carries a generation ID R3 does not know.  "Current Winner's
#               GenID Changes", Actions A5: R3 has to return to NoInfo on
#               it.  Held to the Loser state instead, a router keeps an
#               interface off for a winner that no longer knows it won, for
#               the rest of Assert_Time - three minutes of loss for a
#               neighbour that rebooted in two seconds.  Read out of R3's
#               log, not out of a dump: R4 relearns ED3's membership from
#               its own startup IGMP queries and takes the LAN back within
#               seconds, so the state is a race while the log line is not.
#
#               Then R4's address on the LAN is replaced inside its own
#               subnet, which is the renumber scenario's DHCP lease moving
#               on a segment where an election has already been decided.
#               Both addresses are above R3's, so the election has the
#               answer it had before and nothing but pimd's memory of
#               having won it is under test.  That memory used to be
#               re-derived on every read, by comparing the stored winner
#               against the address the interface has now, so renumbering
#               turned a router into the loser of its own election.
#
#               Downwards, and that is not arbitrary: age_asserts() ages a
#               loser out on "my metric becomes better than the assert
#               winner's", a router misreading its own state ties with
#               itself on both metrics, and the address breaks the tie.
#               Renumbered upwards it beats its own ghost within one timer
#               tick and repairs itself before anything can see it -
#               measured, with the bug reintroduced and the new address
#               above the old one the scenario passed every time.
#
#               What that costs is smaller than it looks, and the scenario
#               says so rather than claiming otherwise: assertion 7 reports
#               the inverted state, which is real, but assertion 8 passes
#               with the bug in place too.  R4 tears its entry down and
#               rebuilds it while the VIF is bouncing, and the rebuilt
#               entry asserts from NoInfo like any other, so the LAN
#               converges on one forwarder either way.  Assertion 8 is kept
#               for that convergence, which nothing else here covers.
#
#               The other half of the same fix - that an assert is given
#               back only on the link the departed neighbour was on, never
#               on another link whose winner happens to hold the same
#               address - is not covered: it needs one router reachable at
#               the same address on two of its own links, which no topology
#               here builds.  Takes about 4 minutes.
#   ssm         IGMPv3 (S,G) membership state on R3, the last hop router,
#               for a group in the 232.0.0.0/8 SSM range.  The only
#               scenario about what IGMP leaves behind on a router rather
#               than about what PIM forwards, and the only one where a
#               group has a source list at all: everywhere else the
#               receiver joins (*,G) and pimd keeps no sources for it.
#
#               ED2 reports two sources, blocks one, and then goes quiet.
#               The membership that is left has to expire on its own, and
#               it used to be unable to: a group held one membership timer,
#               carrying whichever source had reported last, so blocking
#               that source cancelled the only timer the group had while
#               leaving its other source in place.  Nothing then aged the
#               group out, on any timescale.  A leave for the last source
#               still cleaned up, which is why this needs a receiver that
#               stops reporting rather than one that leaves, and why no
#               scenario built on mping could show it: a kernel that joined
#               a group answers every query afterwards, and a receiver
#               taken off the LAN takes the epair, and R3's vif, with it.
#               The reports come from test/igmpv3.c for that reason - one
#               report, sent exactly as asked, and nothing after it.
#               Takes about 90s.
#   ssm-range   The same topology and the same reports, with the SSM range
#               moved off 232.0.0.0/8 by an "ssm-range" in pimd.conf, which
#               is https://github.com/troglobit/pimd/issues/185: routers
#               that let the operator pick the range, Cisco's "ip pim ssm
#               range" among them, and interop with them.
#
#               The configured range replaces the default rather than
#               adding to it, again like Cisco, so one scenario can assert
#               both halves at once: a group in 239.232.0.0/16 has to be
#               treated as source specific, and a group in 232.0.0.0/8 has
#               to stop being.  They are told apart by what R3 keeps for
#               each, per source or a single any-source membership, and by
#               which range gets the link-local virtual RP that config.c
#               installs for SSM.  Takes about 30s.
#   alias       The rpt topology with a second address on R1's interface
#               facing the sender, on a subnet of its own, and a sender
#               that only has an address out of that second subnet.  The
#               only scenario where an interface carries more than one
#               address, so the only one that reaches the alias branch of
#               config_vifs_from_kernel() (src/config.c).
#
#                 ED1 ------------- R1 --- R2 --- R3 --- ED2
#                 10.0.101.10/24    |      (BSR + RP)
#                                   +- 10.0.1.1/24 (the vif)
#                                   +- 10.0.101.1/24 (alias)
#
#               There is one VIF per interface and no more, so the second
#               subnet has nowhere to go except onto the VIF the first one
#               made, as one of the extra subnets pimd.conf calls an
#               "altnet".  pimd used to drop it, with an "alias for vif#N?"
#               at debug level, and never look at the address again.
#
#               On BSD that decides whether anything is forwarded at all.
#               k_req_incoming() (src/routesock.c) asks the VIF table,
#               altnets included, before it asks the kernel, because a
#               route to a connected subnet carries no gateway and the
#               routing socket answers such a lookup with an RPF neighbour
#               of 0.0.0.0 - which every caller reads as "not directly
#               connected".  With the alias dropped, R1 is the designated
#               router for a sender it does not believe is on its LAN:
#               check_register() (src/route.c) never encapsulates, the RP
#               never hears of the source, and the stream dies at the
#               first hop.  Linux cannot show this, netlink.c answers a
#               connected lookup with the destination as its own RPF
#               neighbour.
#
#               R1 has a second address on its link to R2 as well, and
#               R2's route back to the sender names that one, so it is
#               also the only scenario where a next hop is a router's
#               secondary address: the RP's (S,G) Join finds R1 only
#               through the Address List option of R1's Hello, RFC 7761
#               sec. 4.3.4.  Takes about 2 minutes.
#   ifnew       The rpt topology again, and the counterpart to ifgone: an
#               interface that did not exist when pimd started appears
#               under it.  A second link is created between R1 and R2 and
#               addressed while both daemons run, which is a VLAN added to
#               a router in service, a tunnel that comes up, or the ng(4)
#               link mpd5 builds once PPP has negotiated -- the last is
#               where this came from, a BSDRP router whose two PPP links
#               were missing from "pimctl show interface" for the whole
#               life of the daemon because pimd is started from rc(8) six
#               seconds before they exist.
#
#               init_vifs() (src/vif.c) called config_vifs_from_kernel()
#               once and nothing called it again, so the vif table was
#               whatever the kernel had at start-up.  check_vif_state() is
#               not the missing half: it walks the uvifs that scan built,
#               so it only ever flips the interfaces it already knows
#               between up and down.  The only way to a correct table was
#               a restart, which is what this scenario must not need.
#
#               R1 and R2 both get a VIF, so the assertions are not about
#               one daemon's table: a PIM adjacency has to form over the
#               new link, which needs the VIF in the kernel, the two
#               multicast groups joined on it, and Hellos sourced from its
#               address at both ends.
#
#               Two more things only this scenario has.  r1.conf names both
#               new interfaces in phyint lines written before either
#               exists, one of them "disable", so the rescan has to consult
#               pimd.conf and not only the kernel -- the disabled one gets
#               no VIF while the other does, each the control for the
#               other.  And the link is then destroyed and built again
#               under the same name, which has to come back on the vif
#               index it had: a rescan that appended a slot per flap would
#               reach MAXVIFS on a router whose links come and go, which is
#               every router this feature is for.  Takes about 70s.
#
#   ifgone      The rpt topology again, but ED1's link is destroyed while
#               pimd is running and the only question is what R1 does about
#               the VIF that was sitting on it, which is
#               https://github.com/troglobit/pimd/issues/218: a pimd.conf
#               left naming VLANs that had since been deleted, and a router
#               that panicked hours later.
#
#               The errno is the whole scenario.  ifioctl() in
#               sys/net/if.c answers ENXIO for a name it cannot resolve
#               while Linux answers ENODEV, and check_vif_state()
#               (src/vif.c) used to know only the Linux one: on FreeBSD the
#               SIOCGIFFLAGS failure fell through to logit(LOG_ERR), which
#               is exit(-1), so pimd died instead of taking the VIF out of
#               service.  It got there rarely, because the poll it sits in
#               was gated on vifs_down, and nothing sets that when an
#               interface is removed outright - the addresses leave with
#               it, pimd's IP_MULTICAST_IF is then silently ignored and the
#               Hello goes out whatever route the kernel picks instead of
#               failing with ENETDOWN.  So the usual outcome was worse than
#               a crash: the VIF stayed in service forever, pointing at an
#               ifnet the kernel had freed.
#
#               Only ED1's link goes away, so R1 keeps the link to R2 and
#               the run can tell a daemon that survived from one that
#               exited.  That link is then asked what it is still a member
#               of, rather than only whether it still has a neighbour: a
#               neighbour outlives the membership that feeds it by the
#               Hello holdtime, and the leave issued for the interface that
#               went is what takes the groups off the one that stayed.
#               k_leave() named the interface by an address the kernel
#               could no longer place, and in_mcast.c answers that by
#               matching the group on any interface at all.
#
#               The slot R1 keeps for the interface that went is then
#               asked what it still owns.  It keeps its address and its
#               subnet, so that the name has a VIF to come back to (see
#               ifnew), but not the right to refuse the subnet to anybody
#               else: a second interface carrying it has to get a VIF of
#               its own, which is that address failing over to another NIC
#               or the VLAN rebuilt under another name.  Beside it, the
#               control: an interface taken down rather than destroyed
#               goes on owning its subnet, since it is only waiting to
#               come back up.  Takes about 70s.
#
#   renumber    The rpt topology again, and the counterpart to ifgone: the
#               interface stays, its address moves.  R2's address on the
#               R1 link is replaced inside its own subnet while pimd runs,
#               which is a DHCP lease that changed, an ifconfig edit, or a
#               failover address moving between routers.
#
#               The addresses used to be read once, at start-up and on
#               SIGHUP, while the periodic poll looked only at the
#               interface flags, so pimd went on announcing and sourcing
#               PIM from an address the kernel no longer had: the
#               neighbours held it for the full holdtime and could elect it
#               DR, and pimd's own sends left by whatever route the kernel
#               picked.  RFC 7761 sec. 4.3.1 wants a Hello with a zero
#               HoldTime carrying the old address and a Hello carrying the
#               new one, which is what taking the VIF out of service and
#               back in does.
#
#               R2 is the router in the middle, so the assertions can tell
#               a restart confined to one VIF from one that disturbed the
#               router: the adjacency with R1 has to survive untouched.
#               The goodbye Hello is reported rather than asserted, since a
#               poll cannot get ahead of an address that has already gone.
#
#               Both links are asked what they are still a member of as
#               well, for ifgone's reason and against the same bug: the VIF
#               is stopped with the address that has just been deleted, so
#               the membership that should have gone stays on the
#               renumbered interface -- the re-join that follows is refused
#               with "Address already in use", which the run asserts on too
#               -- and another interface's is dropped in its place.  Takes
#               about 50s.
#
#   register-filter
#               The rpt topology with nobody joining the group, and the
#               only scenario about who an RP will accept a Register from:
#               RFC 7761 sec. 6.2's "option to restrict the range of
#               source addresses from which it accepts
#               Register-encapsulated packets", which pimd.conf spells
#               "register-accept-from".  It is A3 in
#               doc/rfc7761-compliance.md, and this covers the half of A3
#               that pimd can be held to.
#
#               R2 is given a prefix that does not cover the address R1
#               registers from, so every Register is refused, and then the
#               prefix is replaced with one that does and the same stream
#               is sent again.  Both halves are needed: an RP that refuses
#               correctly and an RP that never heard a Register at all
#               leave the same absence behind, so the first half on its own
#               is an assertion a broken lab passes.
#
#               What the two halves are compared on is the Register-Stop
#               and whether the DR still encapsulates, not the RP's
#               table.  doc/rfc7761-compliance.md used to propose the
#               table -- "a pimctl show mrt on the RP with no (S,G) in it"
#               -- and it cannot be made to say that.  The RP holds
#               entries for the group either way, and assertion 7 asserts
#               that it does, because it is A3 rather than a flaw in the
#               setup: the kernel decapsulates first, the inner packets
#               reach the register vif, and process_cache_miss()
#               (src/route.c) treats them as the traffic they are.  A
#               shared tree is there for them to land on even with nobody
#               listening, because send_pim_register() fires the
#               Join/Prune timer of the group entry as it registers, so
#               the DR itself joins the tree it is registering to.
#
#               Which address the filter matches is the subtle part and
#               the reason for the prefixes chosen.  send_pim_register()
#               (src/pim_proto.c) sources the Register from the VIF the
#               source is directly connected to, so R1 registers from
#               10.0.1.1 on the sender's LAN, not from the 10.0.12.1 that
#               the RP has in its own neighbour table.  Matching the
#               former is right -- sec. 6.2 restricts by the source
#               address of the Register and sec. 4.4.2 names that
#               outer.src, "the DR's address" -- and a DR with several
#               addresses has several, only one of which the RP ever
#               sees.  The denying prefix is 10.0.12.0/24 for that
#               reason: it covers the address an operator is likelier to
#               reach for and not the one that decides, so a pimd
#               matching the wrong address, or matching nothing at all,
#               fails here rather than passing.
#
#               Nobody joins the group, which keeps R3 and the receiver
#               out of the RP's table and the scenario down to the two
#               routers it is about.  It is not what makes the table
#               readable -- nothing does.
#
#               "netstat -sp pim" in R2's vnet is where the packet half of
#               A3 is counted: pim_input() (sys/netinet/ip_mroute.c) bumps
#               that counter and hands the inner packet to the register
#               vif before the daemon is given the header, so the count
#               rises for every Register pimd refuses.  That is why
#               pimd.conf.5 points an operator who needs the packet
#               stopped at a packet filter for IP protocol 103, and why
#               the entry in doc/rfc7761-compliance.md stays open.
#               Takes about 2 minutes.
#
#   static-rp   The rpt topology with nothing forwarded, and the only
#               scenario where a router has an RP of its own configuration
#               beside the one the BSR advertises.  RFC 7761 sec. 4.7
#               requires both to be supported; it gives no precedence rule
#               between them, and this is not about precedence.
#
#               R3 gets one "rp-address" line.  With no group after the
#               address that covers 224.0.0.0/4 (src/config.c), which is
#               the prefix r2.conf's Candidate-RP is advertised under, so
#               the configured entry and the learned ones share a single
#               grp_mask_t -- and that is the whole mechanism.  A Bootstrap
#               stamps the prefix with its own fragment tag, and the
#               garbage collector at the end of receive_pim_bootstrap()
#               deletes every RP on a stamped prefix whose own tag differs.
#               The configured entry never carried that tag, so the first
#               Bootstrap deleted it.
#
#               The configured RP is R2's address on the R3 link while the
#               BSR advertises R2's address on the R1 link: the same router
#               under two addresses, which they have to be.  add_rp_grp_entry()
#               (src/rp.c) merges an advertisement for an RP and prefix it
#               already holds into the existing entry, so with one address
#               a configured entry that survived would look exactly like
#               one the BSR had just put back.
#
#               Step 5 is what it cost rather than what it was.  Only
#               restart() reads g_rp_hold again (src/main.c), so the
#               configured RP did not come back on its own: a router that
#               lost it this way aged the learned RP set out when the BSR
#               died and was left with no RP at all until somebody sent it
#               a SIGHUP.  The scenario kills the BSR and asserts the
#               configured RP is still there.  Takes about 3 minutes, most
#               of it that wait.
#
#   anycast     The chain with R2 and R3 both the RP, and the only scenario
#               where two routers are: RFC 4610's Anycast-RP, where the
#               members of a set hold one RP address and copy each other
#               the Registers they are sent.  $ANY_ADDR is on lo0 in both,
#               R1's route to it goes to R2, and R3 is where ED2's shared
#               tree ends, so the source registers to one member and the
#               receiver joins at the other -- the only arrangement in
#               which the copies are what makes the traffic arrive.
#
#               It starts without a set, as the control: the same source
#               and a receiver behind R3 that hears nothing.  Then both get
#               the anycast-rp lines, and the scenario asserts the copy
#               from R2 to R3 -- a Null-Register, since FreeBSD hands pimd
#               only the headers of a data Register -- its TTL one less
#               than the Register's, R3 holding the (S,G) before anybody
#               joins and not copying it on, that (S,G) living past its
#               own timeout on nothing but the copied probes, and at last a
#               receiver behind R3 reached.  Then two things about what a
#               member takes from whoever sends it Registers: a burst of
#               600 copied only up to the per-second budget, data copies
#               turning into Null-Registers first, and register-sg-limit,
#               which R2 runs with at 4, holding some of six sources a
#               Register each names and refusing the rest.  Takes about 5
#               minutes, most of it that timeout.
#
#   anycast-dr  The same set, moved one router upstream: R1 and R3 hold
#               $ANY_ADDR, and R2 is a plain router whose route to it goes
#               to R1.  R1 is then the RP of the group and the DR of the
#               source at once, and receives no Register for it at all --
#               which is the case RFC 4610 sec. 5.1 means by a source
#               registered by "the router itself".  The only way R3 learns
#               of it is a Register R1 sends it from its own member
#               address, whole this time, from the kernel's upcall.
#
#               Starts without a set as anycast does, then asserts the data
#               Register from R1 to R3, R1 honouring R3's Register-Stop and
#               probing it with Null-Registers afterwards, and a receiver
#               behind R3 reached, and last a member's Register-Stop for an
#               entry R1 is not registering, which has to leave that
#               entry's Register-Suppression timer alone.  Takes 2 to 3
#               minutes, depending on when the probe falls due.
#
#   crafted     The rpt topology with nothing forwarded, and the only
#               scenario whose messages pimd did not build.  Every other
#               test here has pimd at both ends, so the only messages pimd
#               ever parses are messages pimd wrote: a field it refuses to
#               encode wrongly is a field nothing here can test it on, and
#               most of doc/rfc7761-compliance.md is out of reach for that
#               reason.  test/pimsend.c is the way past it -- one PIM
#               message, any field set to anything, sent once -- and this
#               is its first user.
#
#               ED1 sends them, which is the point: a host on a subnet the
#               router has a VIF on is the position RFC 7761 sec. 6.2 is
#               about, and all an attacker needs.  A second address on
#               ED1's interface gives the scenario a stranger and a
#               neighbour on the same link at the same time, which is what
#               tells a check that refuses a stranger from one that
#               refuses everybody.
#
#               What is guarded is the whole packet format section of
#               doc/rfc7761-compliance.md -- the PIM version and the
#               destination of sec. 4.9, the address family and encoding
#               type and the mask length of sec. 4.9.1, the B and Z bits of
#               an encoded group, the 0xffff Holdtime of sec. 4.9.5 and the
#               Null-Register dummy header checksum of sec. 4.9.3 -- plus
#               sec. 6.2's "SHOULD NOT accept protocol messages from a
#               router from which it has not yet received a valid Hello
#               message", in the unicast branch of
#               receive_pim_bootstrap(); RFC 5059 sec. 3.5.1's No-Forward
#               bit, which waives the RPF check and is not forwarded on;
#               sec. 6.2's other option, "accept-nbr-from", which R1 runs
#               the whole scenario with configured so that every assertion
#               above is a soak test of it; sec. 4.3.4's Hello Address
#               List, which pimd sends too, but an encoder pimd did not
#               write is the only one that can tell a list pimd reads from
#               a list pimd reads the way it writes one; the (S,G,rpt)
#               machines of sec. 4.5.3 and 4.5.7, which between two pimds
#               the override Join hides, so pimsend plays both the router
#               that prunes and the one that overrides, and the
#               rpt-prune-limit that caps the state those Prunes make; and the two rules of sec. 4.8.1
#               about what an SSM-unaware router may still send: no shared
#               tree for a group in the SSM range, and a Register for one
#               answered with a Register-Stop rather than dropped in
#               silence.  Neither pimd nor the EOS of freebsd-interop.sh
#               will send either message, so pimsend is the only way to
#               ask.
#
#               The order the steps run in is not cosmetic.  The holdtime
#               one needs the RPF neighbour toward the source to be a PIM
#               neighbour, so it runs before the BSR is stopped; and the
#               unicast Bootstrap branch is reachable only while a router
#               knows no dynamic RP, which is where RFC 5059 sec. 3.5.2
#               puts it and why the step after it kills the BSR and waits.
#
#               Every refusal has its positive control beside it: the same
#               Join correctly formed, the same Bootstrap once its sender
#               has said Hello.  Without them a parser that dropped
#               Join/Prunes altogether would pass the whole scenario, and
#               nothing else in this file sends one that R1 acts on.  This
#               is also the only scenario that asks for pim_jp debugging,
#               see set_scenario(): the lines it reads are behind it.
#               Takes about 4 minutes, most of it the wait for the RP to
#               age out.
#
#   fuzz        The same topology and the same sender, with messages that
#               are wrong in no particular way rather than in one named way.
#               pimsend builds one of each type, flips a few bytes of its
#               body, computes the checksum afterwards -- otherwise the
#               mutant dies at the checksum test and never reaches a parser
#               -- and sends five hundred of them, a fresh draw per packet
#               and the same draw on any machine from the same seed, so an
#               input that trips something can be sent again.
#
#               Where crafted asserts what a parser does with a field, this
#               is about the combination nobody thought of, and it is the
#               only test here that puts that to a *running* daemon: the
#               in-process harnesses of test/fuzz/ explore in a minute what
#               this sends in an hour, but they call the parsers with a
#               fabricated vif table and no neighbours, while these arrive
#               at a pimd that has a neighbour, an RP set, a kernel MFC and
#               a register vif behind it.
#
#               Under SANITIZE=yes the sanitizers are the assertion.
#               Without them the scenario can only say that pimd stayed up,
#               kept its neighbours and its RP set and still parsed a
#               well-formed Join afterwards -- worth asserting, a daemon
#               any host on its LAN can silence being a bug of its own, but
#               not the same question.  FUZZ_COUNT, FUZZ_FLIPS and
#               FUZZ_SEED are the knobs, and a hunt wants a new seed rather
#               than a longer run of the same one.  Takes under a minute.
#
# Scenarios run in parallel, several labs at a time on one host: -s picks
# a slot, 0 to 31, and every name the lab puts on the host carries it, so
# slot 3's jails, epairs, bridges and work directory are not slot 0's.
# The addresses inside the jails are the same in every slot and can be,
# a vnet jail having an interface namespace and a forwarding cache of its
# own.  "-j N run all" does the bookkeeping: N scenarios at a time, each
# in a slot of its own, longest first, each one's output printed whole
# when it ends.  Measured on a 16-core host, 6m55s at -j 14, against the
# half hour and more they take one after another.  More jobs barely help
# past a handful because keepalive is a floor no job count moves: it has
# to outlive PIM_DATA_TIMEOUT, so it runs 240s whatever else is happening,
# and its local-sg-limit steps after that.
#
# Two things are worth knowing before turning -j up.  The first is that
# every assertion here is a poll against a timeout, so a slower lab can
# fail an assertion rather than merely take longer -- though measured
# here the cost of a pool is not load: fourteen labs at once is a load
# average under one, and -j 14 passed all fourteen scenarios.
#
# What a pool does change is which states the scenarios reach, and that
# is worth having rather than working around.  shared-lan-spt failed its
# assert election in four -j 4 runs out of four while passing alone in
# every slot, and it was right to: R3 never set SPTbit for the source,
# so it asserted as an RPT forwarder, the two MRTF_SPT guards in
# assert_machine() (src/pim_proto.c) had each router decline the other's
# Assert, and the LAN kept two forwarders for good.  The pool is simply
# what left a router the Assert loser on its own RPF interface often
# enough to get there; a sequential run never provoked it.  Fixed in
# 076343d -- update_sptbit() (src/route.c) now asks the shared tree's
# olist rather than whether a (*,G) entry exists -- and "-j 4 run all"
# has been 14 of 14 since.  Run the pool for that, not despite it.
#
# The second is net.inet.ip.mcast.loop, which is not VNET-ized and is the
# one piece of host state the slots share: they hold it between them and
# the last one out puts it back, see disable_mcast_loop().
#
# Usage:
#   ./lab.sh [-s SLOT] start [scenario]  build the lab, start pimd on its routers
#   ./lab.sh [-s SLOT] check [scenario]  run the assertions (start must have run)
#   ./lab.sh [-s SLOT] run   [scenario]  start + check + stop, exit 0 if all pass
#   ./lab.sh [-s SLOT] stop              tear that slot down
#   ./lab.sh -j 4 run all                every scenario, four at a time
#   ./lab.sh -j 3 run shared-lan shared-lan-spt assert-recover
#                                                three of them, all at once
#
# where scenario is "rpt" (default), "keepalive", "rp-lasthop",
# "rp-offpath", "gif-tunnel", "gif-tunnel-staticrp", "shared-lan",
# "shared-lan-spt", "assert-recover", "ssm", "ssm-range", "alias",
# "ifnew", "ifgone", "renumber", "register-filter", "crafted", "fuzz",
# "static-rp", "anycast", "anycast-dr", or "all"
# for run.
#
# Requires: root (via sudo), VIMAGE kernel, ip_mroute.ko, if_bridge.ko for
# the shared segment scenarios, and a built pimd tree in $PIMD_SRC (./autogen.sh &&
# ./configure && make).  With NETLINK=yes, that tree has to be configured
# --enable-netlink and netlink.ko has to be loadable.
#
# On Linux the same scenarios run over named network namespaces, veth pairs
# and Linux bridges instead: root, iproute2, ethtool, a kernel with
# CONFIG_IP_MROUTE and CONFIG_IP_PIMSM_V2, and NETLINK is always yes there.
# Everything that touches the host is in lab-freebsd.sh or lab-linux.sh,
# picked by uname(1).
#
# SANITIZE=yes runs the scenarios against a pimd built with
# -fsanitize=address,undefined and fails any scenario whose daemons
# reported anything, on either system; see the knob below.
#
# COVERAGE=yes runs them against a pimd built --enable-coverage and leaves
# the counters behind for test/coverage.sh to turn into a table of which
# lines the suite reaches; see the knob below and doc/README-coverage.md.

set -eu

# The options come before the command, "$0 -s 3 run rpt", and are read
# here rather than beside the dispatch at the foot of the file: -s picks
# the slot, and the slot is what every name in the next hundred lines is
# derived from.  usage() cannot be called yet for the same reason, so a
# bad option says where to find it instead of printing it.
SLOT=${SLOT:-0}
JOBS=${JOBS:-1}
HELP=
while getopts "s:j:h" opt; do
	case "$opt" in
	s) SLOT=$OPTARG ;;
	j) JOBS=$OPTARG ;;
	h) HELP=yes ;;
	*) echo "EXIT: run \"$0 -h\" for usage" >&2; exit 2 ;;
	esac
done
shift $((OPTIND - 1))

case $JOBS in
""|*[!0-9]*|0) echo "EXIT: -j wants a job count of 1 or more, not \"$JOBS\"" >&2; exit 1 ;;
esac

# Root needs no sudo, and the places this runs unattended -- CI in a VM,
# a jail host -- often do not have it installed at all.  An explicitly
# empty SUDO= is honoured either way; ${SUDO:-sudo} would have quietly
# put sudo back.
if [ "$(id -u)" -eq 0 ]; then
	SUDO=${SUDO-}
else
	SUDO=${SUDO-sudo}
fi
# The tree this script lives in, so it tests the pimd next to it rather
# than whatever is installed.  Override to point somewhere else.
PIMD_SRC=${PIMD_SRC:-$(cd "$(dirname "$0")/.." && pwd)}

# Where this script and the files it sources are, which PIMD_SRC need not be
LAB_DIR=$(cd "$(dirname "$0")" && pwd)

# This script, by a path that works from anywhere: "run -j" starts a slot by
# running it again, and "$0" is whatever the caller typed -- `sh lab.sh` from
# this directory leaves it without a slash, which the shell then looks for in
# PATH and does not find.  Run through sh, so it needs no execute bit either.
LAB_SELF=$LAB_DIR/${0##*/}

# Which of the labs this invocation is, 0 to 31, from -s.  Every name that
# lives on the host carries it -- the jails, the epairs, the bridges, the
# work directory, the interface group -- so several scenarios can be built
# on one machine at once and none of them can see, or tear down, another's.
# Slot 0 is spelled the way this lab always was, "pimd_r1", "epair101a",
# /tmp/pimd-test, so a single run reads exactly as it used to.
#
# What is deliberately *not* per slot is the topology inside the jails:
# every slot uses the same 10.0.0.0/8 addresses, and can, because a vnet
# jail has an interface namespace, a routing table and a multicast
# forwarding cache of its own.  Only the host side has to be kept apart,
# and the epair unit number is where that is done -- slot N turns 101 into
# N101, which no other slot can create and which stays well inside both
# IFNAMSIZ and the cloner's unit range.
#
# The one thing the slots still share is net.inet.ip.mcast.loop, which is
# not VNET-ized; see disable_mcast_loop() for how they take turns with it.
# 31 is where the kernel stops, not where the lab does: an epair unit is
# the slot followed by this lab's own three digits, and if_clone refuses a
# unit above 32767 -- slot 32 would ask for epair32863.
case $SLOT in
[0-9]|[12][0-9]|3[01]) ;;
*) echo "EXIT: slot must be 0 to 31, not \"$SLOT\"" >&2; exit 1 ;;
esac
if [ "$SLOT" -eq 0 ]; then
	TAG=
else
	TAG=$SLOT
fi

# The host-visible names, all derived from the slot.  $EPU is the
# deliberately capitalised epair of renames(), and has to carry the tag
# the same way its lower case twin does.
EP=epair$TAG
EPU=Epair$TAG

# The host side of the lab -- the boxes, the links, and what the kernel
# makes of pimd's requests -- lives in a file per system, see its header.
# Sourced this early because a backend may set a default the rest of the
# variables below are derived from, NETLINK on Linux.
case $(uname -s) in
FreeBSD) . "$LAB_DIR/lab-freebsd.sh" ;;
Linux)   . "$LAB_DIR/lab-linux.sh" ;;
*)       echo "EXIT: no lab backend for $(uname -s)" >&2; exit 1 ;;
esac

# Set in the environment it is one directory for every slot, which cannot
# work once more than one of them runs; run_parallel() refuses it.
WORKDIR_PINNED=${WORKDIR:+yes}
WORKDIR=${WORKDIR:-/tmp/pimd-test$TAG}
GROUP=${GROUP:-225.1.2.3}
GROUP_DEFAULT=$GROUP
SCENARIO=${SCENARIO:-rpt}

# Every scenario, in the order "run all" walks them one at a time, and the
# same set ordered by how long each takes for when they run several at a
# time.  Longest first is not a preference, it is what keeps a pool busy:
# started in the written order a pool of four spends its last five minutes
# running keepalive alone with three slots idle, because the longest
# scenario in the list was picked up last.
SCENARIOS="rpt solo privsep keepalive rp-lasthop rp-offpath gif-tunnel gif-tunnel-staticrp
	   shared-lan shared-lan-spt assert-recover ssm ssm-range alias
	   ifnew ifgone renumber register-filter crafted fuzz static-rp anycast anycast-dr"
SCENARIOS_BY_LENGTH="keepalive anycast shared-lan assert-recover anycast-dr shared-lan-spt
		     gif-tunnel-staticrp rp-lasthop rp-offpath gif-tunnel
		     rpt register-filter alias crafted static-rp ssm fuzz ifnew ifgone
		     renumber ssm-range solo privsep"

# keepalive: groups the source blasts at, and how long the entries must
# survive.  KEEP_SECONDS has to exceed PIM_DATA_TIMEOUT in src/pimd.h.
KEEP_GROUP=${KEEP_GROUP:-239.1.1.5}
KEEP_NUM=${KEEP_NUM:-3}
KEEP_SECONDS=${KEEP_SECONDS:-240}
# ... and the groups a second sender floods once those have been shown to
# stay, none of which local-sg-limit leaves room for
KEEP_FLOOD_GROUP=${KEEP_FLOOD_GROUP:-239.1.2.1}
KEEP_FLOOD_NUM=${KEEP_FLOOD_NUM:-64}

# Which RPF backend the tree under test was built with, "routing socket"
# by default and "netlink" with NETLINK=yes.  The string is what pimctl
# show status prints, i.e. what src/routesock.c and src/netlink.c call
# themselves.
NETLINK=${NETLINK:-no}
if [ "$NETLINK" = yes ]; then
	RPF_BACKEND="netlink"
else
	RPF_BACKEND="routing socket"
fi

# SANITIZE=yes runs the scenarios against a pimd built with
# -fsanitize=address,undefined and fails a scenario that made either
# sanitizer say anything, whatever its assertions found.  It does not build
# that pimd: point PIMD_SRC at a tree configured for it, and check_req()
# asks the binary whether it really is one rather than take the tree on
# trust, the way the NETLINK knob above does.
#
# Each daemon is given a log of its own to write reports to, because the
# two sanitizers behave differently and neither is any use inside the pimd
# log alone: ASan stops the daemon at its first error, which the assertions
# notice by themselves, while UBSan prints and carries on -- so its
# findings would leave with the work directory of a scenario that passed.
#
# Leak checking is off by default, ASan turning it on at exit on Linux:
# what leaks in a daemon that is being torn down is a hunt of its own.
# SAN_ASAN_OPTIONS="detect_leaks=1" asks for it, and then "run" is the
# command to use -- the daemons have to exit for a leak report to exist,
# which "run" sees to before it looks and "check" on a running lab cannot.
# The log_path is the lab's to set, the reports going to the work
# directory beside the logs of the run that made them.
SANITIZE=${SANITIZE:-no}
SAN_DIR=$WORKDIR/sanitizer
SAN_ASAN_OPTIONS=${SAN_ASAN_OPTIONS:-detect_leaks=0}
SAN_UBSAN_OPTIONS=${SAN_UBSAN_OPTIONS:-print_stacktrace=1}

# COVERAGE=yes runs the scenarios against a pimd built --enable-coverage,
# so that what they reach can be counted rather than read.  It does not
# build that pimd either, and check_req() asks the binary rather than the
# tree, as the two knobs above do.
#
# It changes one thing about the run: the daemons are given --no-privsep.
# A .gcda file is written by the process that exits, at a path fixed when
# it was compiled and with an open(2) -- and the unprivileged half of a
# separated pimd can do neither.  The chroot took that path away on every
# system, and on Linux open(2) is not on the seccomp allowlist, so the
# half that runs every parser and every state machine would be killed for
# asking rather than counted.  The privsep scenario is the exception: the
# split is what it asserts, so it keeps it, and only its privileged half
# is counted.
#
# The other bound is SIGKILL, which no exit handler survives: stop() ends
# the daemons with SIGTERM, but restart_pimd() cuts one off on purpose --
# assert-recover, which needs a router that did not say goodbye for the
# generation ID event to happen at all, and privsep, for the control it
# ends on -- and that incarnation's counters are gone.  Both bounds are written down in
# doc/README-coverage.md, because a number nobody knows the edges of is
# worse than none.
COVERAGE=${COVERAGE:-no}

# What the daemons are run with, empty unless a knob above asks for
# something.  The lab wraps every privileged command in sudo(8), which
# strips the environment, so this is passed to each daemon through env(1)
# rather than exported here; see box_daemon() in the backends.
PIMD_ENV=
if [ "$SANITIZE" = yes ]; then
	PIMD_ENV="ASAN_OPTIONS=$SAN_ASAN_OPTIONS:log_path=$SAN_DIR/asan"
	PIMD_ENV="$PIMD_ENV UBSAN_OPTIONS=$SAN_UBSAN_OPTIONS:log_path=$SAN_DIR/ubsan"
fi

# How long the "pimd is alive" step of a scenario waits for a daemon to
# answer on its socket.  start() waits for the first router itself, through
# verify_rpf_backend(), and the rest are usually up by the time the first
# assertion asks -- usually: a host running many labs at once starts them
# all at once too, and a sample taken once has failed a scenario whose pimd
# was still opening its sockets.  Every other assertion here polls; so does
# this one now.
PIMD_START_WAIT=${PIMD_START_WAIT:-20}

# pimd debug flags, e.g. DEBUG="-l debug -d mrt,rpf" or "-l debug -d all"
DEBUG=${DEBUG:-"-l debug -d mrt,rpf,pim_register,pim_bootstrap"}

# Kept so set_scenario() can put it back: "run all" walks the scenarios in
# one shell, and crafted needs a subsystem the rest do not.
DEBUG_DEFAULT=$DEBUG

PIMD="$PIMD_SRC/src/pimd"
PIMCTL="$PIMD_SRC/src/pimctl"
MPING="$WORKDIR/mping"
IGMPV3="$WORKDIR/igmpv3"
PIMSEND="$WORKDIR/pimsend"
# mping joins the group it sends to, which would give the (S,G) entries a
# leaf and hide the bug the keepalive scenario is after.  That scenario
# needs a source that only sends, so it gets its own little sender.
MSEND="$WORKDIR/msend"

BOXES="ed1 r1 r2 r3 ed2"
ROUTERS="r1 r2 r3"
EPAIRS="${EP}101 ${EP}112 ${EP}123 ${EP}203"
ED2_IF=${EP}203b

# Kept so set_scenario() can put them back: "run all" walks the scenarios
# in one shell, and a shared segment scenario replaces all four
DEFAULT_BOXES=$BOXES
DEFAULT_ROUTERS=$ROUTERS
DEFAULT_EPAIRS=$EPAIRS
DEFAULT_ED2_IF=$ED2_IF

# shared-lan: the two right hand links become bridged segments, carrying two
# more routers and a second end device.  Only the "b" end of a bridged epair
# goes into a jail, its "a" end stays on the host as a bridge member, so
# create_lans() has to create those before the jails: create_box() creates
# the pairs whose "a" end the box itself owns, and it owns none of them.
# epair510, the ordinary point-to-point link from R5 down to ED2, is left to
# create_box() like every link in the other scenarios.
SHARED_BOXES="ed1 r1 r2 r3 r4 r5 ed2 ed3"
SHARED_ROUTERS="r1 r2 r3 r4 r5"
BR_UPSTREAM=bridge${TAG}223
BR_RECEIVER=bridge${TAG}303
BR_UPSTREAM_EPAIRS="${EP}223 ${EP}323 ${EP}423"
BR_RECEIVER_EPAIRS="${EP}503 ${EP}303 ${EP}403 ${EP}603"
SHARED_EPAIRS="$BR_UPSTREAM_EPAIRS $BR_RECEIVER_EPAIRS ${EP}510"

# rp-offpath: one extra link closes the chain into a triangle, straight
# from the first hop router to the last hop one, so the RP no longer sits
# on the path the traffic takes once the shortest path tree is up.
OFFPATH_EPAIRS="$DEFAULT_EPAIRS ${EP}113"

# solo: one router, an end device on each of its two LANs and nothing else.
# The link to the receiver is numbered 104 rather than 102 or 103, which
# would read as a link to a second or third router; there is none here.
SOLO_BOXES="ed1 r1 ed2"
SOLO_ROUTERS="r1"
SOLO_EPAIRS="${EP}101 ${EP}104"
SOLO_ED2_IF=${EP}104b
SOLO_RCV_ADDR=${SOLO_RCV_ADDR:-10.0.4.10}
# The address r1.conf names its candidacies by, so the RP is this and not
# "whatever address is highest"
SOLO_RP_ADDR=${SOLO_RP_ADDR:-10.0.1.1}
OFFPATH_R1_IF=${EP}113a
OFFPATH_R3_IF=${EP}113b
OFFPATH_R1_ADDR=10.0.13.1
OFFPATH_R3_ADDR=10.0.13.3
# The RP and the BSR sit on R2's interface facing the last hop router, so
# R3 is directly connected to both, see write_configs()
OFFPATH_RP_ADDR=10.0.23.2

# ifnew: the links that appear under a running pimd.  Neither is created
# with the boxes, check_ifnew() builds them once the daemons are up, so
# they are here only to be named and to be cleaned up.
#
# $IFNEW_EP is a second R1-R2 link, addressed at both ends, and the one an
# adjacency has to form over.  $IFNEW_OFF_EP appears on R1 alone -- its
# other end is left on the host, unaddressed, since nothing has to answer
# on it -- and r1.conf disables it by name, so it is the control beside
# the other: a rescan that reads only the kernel gives both a VIF.
#
# The unit numbers are two no other scenario uses; 212 reads as the second
# link between R1 and R2 and 219 as a second one from R1 to nowhere.
IFNEW_EP=${EP}212
IFNEW_IF=${IFNEW_EP}a
IFNEW_PEER_IF=${IFNEW_EP}b
IFNEW_ADDR=10.0.21.1
IFNEW_PEER_ADDR=10.0.21.2
IFNEW_PREFIX=24
IFNEW_OFF_EP=${EP}219
IFNEW_OFF_IF=${IFNEW_OFF_EP}a
IFNEW_OFF_ADDR=10.0.29.1
IFNEW_EPAIRS="$IFNEW_EP $IFNEW_OFF_EP"
# The link R1 and R2 had all along, which none of this may disturb
IFNEW_KEPT_ADDR=10.0.12.2

# How long pimd may take to notice.  It acts on the kernel's own
# notification, which reaches it in about a second; the periodic rescan
# that is the floor under that runs every 60s (VIF_RESCAN_PERIOD in
# src/vif.c), so a wait of 30 is generous for the event path and still
# proves it is the event path being used.
IFNEW_WAIT=${IFNEW_WAIT:-30}

# Everything any scenario can create, so stop() cleans up without having to
# be told which one was running.
ALL_BOXES="ed1 r1 r2 r3 r4 r5 ed2 ed3"
ALL_EPAIRS="$EPAIRS $SHARED_EPAIRS ${EP}113 ${EP}104 $IFNEW_EPAIRS"

# Source and RP addresses the assertions expect.  set_scenario() puts
# SRC_ADDR back from the default, the alias scenario moves it.
SRC_ADDR=10.0.1.10
SRC_ADDR_DEFAULT=$SRC_ADDR
RP_ADDR=10.0.12.2

# alias: a second address on R1's interface facing ED1, on a subnet of its
# own, and a sender that only has an address out of that subnet.  The vif
# keeps the primary address, so reaching the sender at all depends on
# config_vifs_from_kernel() (src/config.c) keeping the second subnet as an
# altnet of the same vif.
ALIAS_IF=${EP}101b
ALIAS_ADDR=10.0.101.1
ALIAS_NET=10.0.101.0/24
ALIAS_SRC_ADDR=10.0.101.10

# alias, the Address List half: a second address on R1's link to R2, in the
# same subnet as the first, and R2's route back to the sender pointed at it.
# The only next hop in any lab that is a router's secondary address, so the
# only one where the RP's Join has no neighbour to go to unless R1's Hello
# said which router the address belongs to (RFC 7761 sec. 4.3.4).
ALIAS_UP_IF=${EP}112a
ALIAS_UP_ADDR=10.0.12.11

# rp-lasthop: the RP moves to R3, on the interface facing the receiver, so
# the router that is RP is also the one with the directly connected member.
RCV_ADDR=10.0.3.10
RPLH_ADDR=10.0.3.1

# shared-lan: the shared segment is 10.0.3.0/24, with three PIM routers and
# one end device on it.  The addresses are what decide the two elections
# held there, and they are picked so the elections land on different
# routers: PIM takes the highest address, so R4 is the DR, IGMP takes the
# lowest, so R5 is the querier.
#
# R5 must not be the DR, hence its address at the bottom of the range.  Its
# RPF interface for the group is the shared LAN itself, so an oif there
# would be its own incoming interface and calc_oifs() would drop it: were R5
# the DR, ED3's membership would give nobody a usable oif and the scenario
# would have one forwarder instead of two.
SL_R3_IF=${EP}303b
SL_R4_IF=${EP}403b
SL_R5_IF=${EP}503b
SL_R3_ADDR=10.0.3.2
SL_DR_ADDR=10.0.3.3
SL_QUERIER_ADDR=10.0.3.1
SL_ED3_ADDR=10.0.3.10

# The address the shared LAN's DR starts at.  assert-recover replaces it,
# see AR_DR_ADDR below, so set_scenario() puts this one back for the two
# scenarios that want it.
SL_DR_ADDR_DEFAULT=$SL_DR_ADDR

# assert-recover: the DR's two addresses, and which is which matters.  The
# renumbering has to move it *down*.
#
# age_asserts() (src/pim_proto.c) re-runs the comparison that ages a loser
# out once per pass, and a router that misreads its own winner state as
# loser state is carrying its own old metric as the winner's: the two tie
# on preference and on metric, and the address settles it.  Renumbered
# upwards such a router beats its own ghost on the tiebreak within one
# timer tick, and the state repairs itself before anything on the LAN can
# notice -- measured here, with the bug reintroduced and the new address
# above the old one the scenario passed every time.  Renumbered downwards
# it loses to the ghost and stays stuck until the Assert Timer expires,
# which is the behaviour this is here to catch.
#
# Both are above $SL_R3_ADDR, so R4 wins the election before and after and
# stays the DR: the election's answer is not what is under test.
AR_DR_ADDR=${AR_DR_ADDR:-10.0.3.200}
AR_DR_NEW=${AR_DR_NEW:-10.0.3.100}

# How long an election is given to settle, and how long the stream that
# drives it runs for.  An election is only ever run while data is arriving
# on the segment, so the stream has to outlast a pimd restart, a
# renumbering and the four convergences between them.
AR_WAIT=${AR_WAIT:-90}
AR_PKTS=${AR_PKTS:-600}

# ED3 joins the group on a port of its own.  IGMP membership is per group,
# not per port, so R4 sees a report and takes the leaf, while the stream
# ED1 sends to $GROUP:4321 never reaches ED3's socket and it answers none of
# it.  That keeps every reply the sender counts a reply from ED2, at the far
# end of the tree, rather than one from a member sitting on the LAN itself.
SL_JOIN_PORT=${SL_JOIN_PORT:-4322}

# shared-lan: the route whose metric decides the assert election of step 12.
# Both contenders forward the group off the shared tree, so the metric they
# compare is rpt_assert_metric(G,I), MRIB.metric(RP(G)) -- the cost of the
# route to the RP, and not of the one to the source.  R3 and R4 have the
# same one, out of routes() below; route_metrics() starts both at
# SL_METRIC_FAR and step 12 moves one of them to SL_METRIC_NEAR, which is
# the only thing in this file that makes two pimds advertise different
# metrics at all.
SL_RP_NET=10.0.12.0/24
SL_RP_GW=10.0.23.2
SL_METRIC_NEAR=${SL_METRIC_NEAR:-1}
SL_METRIC_FAR=${SL_METRIC_FAR:-50}
# One re-election is a 20s unicast routing check plus the 5s timer tick
# plus the election itself; the wait is long enough to tell a slow lab from
# a metric that never moved.
SL_METRIC_WAIT=${SL_METRIC_WAIT:-120}
SL_METRIC_PKTS=${SL_METRIC_PKTS:-400}

# Replies the sender must get back before the stream counts as forwarded.
# The first seconds are always lost while PIM registers the source with
# the RP and the receiver's join climbs the tree.
MIN_REPLIES=${MIN_REPLIES:-20}

# rp-lasthop: packets ED1 sends at one per second, how many of them have
# to make it to ED2, and how many registers R3 may decapsulate along the
# way.  R3 runs its SPT check every 10s (see write_configs), so it should
# join the shortest path tree and register-stop R1 within the first couple
# of intervals; one register per data packet is the failure the issue
# describes.
STREAM_PKTS=${STREAM_PKTS:-40}
MIN_RECEIVED=${MIN_RECEIVED:-20}
MAX_REGISTERS=${MAX_REGISTERS:-25}

# Seconds to let PIM settle before the gif-tunnel-staticrp stream, see
# check_gif_staticrp() for why that scenario needs it and the others do not.
SETTLE=${SETTLE:-45}

# ssm: two sources reported for one SSM group, and how long a membership
# then lives without a report.  IGMP_ROBUSTNESS_VARIABLE (3) *
# SSM_QUERY_INTERVAL + IGMP_QUERY_RESPONSE_INTERVAL (10), see r3.conf in
# write_configs().  SSM_SRC1 and SSM_SRC2 only have to be routable from
# R3, they never send: this scenario is about membership state, not
# forwarding.
SSM_QUERY_INTERVAL=${SSM_QUERY_INTERVAL:-5}
SSM_TIMEOUT=${SSM_TIMEOUT:-25}
SSM_SRC1=${SSM_SRC1:-10.0.1.10}
SSM_SRC2=${SSM_SRC2:-10.0.1.11}
SSM_MAX_SOURCES=${SSM_MAX_SOURCES:-256}

# A second SSM group, used only by the any-source assertion, and separate
# from $GROUP on purpose: accept_group_report() (src/igmp_proto.c) takes the
# "found it, reset its timer" path for a group it already holds, so a v2
# report for a group the assertions above have built state for never reaches
# the code that reads the report's destination as a source.  Reproducing
# that needs a group nothing has reported yet.
SSM_V2_GROUP=${SSM_V2_GROUP:-232.1.1.9}

# ssm-range: the range pimd.conf configures, a group inside it, and the
# group from the default range that has to stop being source specific once
# the configured one replaces it.
SSMR_RANGE=${SSMR_RANGE:-239.232.0.0/16}
SSMR_GROUP=${SSMR_GROUP:-239.232.1.1}
SSMR_OLD_GROUP=${SSMR_OLD_GROUP:-232.1.1.1}
SSMR_DEFAULT_RANGE=232.0.0.0/8

# static-rp: the RP R3's pimd.conf names, and how long the learned one may
# take to age out once the BSR is killed.  R2's address on the R3 link, so
# the configured RP and the advertised one ($RP_ADDR, R2's address on the R1
# link) are the same router under two addresses and cannot be merged into
# one entry -- see check_static_rp() for why that matters.
STATICRP_ADDR=${STATICRP_ADDR:-10.0.23.2}
STATICRP_WAIT=${STATICRP_WAIT:-180}

# A PIM Register carrying nothing but the IP header of the packet it stands
# for: the four byte PIM header and a 20 byte IPv4 header and its own four
# byte reserved field.  What a Null-Register is, and what FreeBSD hands pimd
# of a data Register as well, see REGISTER_UPCALL in the backends.
REG_NULL_LEN=${REG_NULL_LEN:-28}

# anycast: the RP address both members hold on lo0, the unique address each
# one is a member under -- their ends of the R2-R3 link -- the group the
# set is tested on, and how long the (S,G) on R3 has to outlive with nobody
# joined.  ANY_REFRESH has to exceed PIM_DATA_TIMEOUT in src/pimd.h, or the
# entry would pass without anything refreshing it.  ANY_DR is the address
# R1 registers from, the VIF of the source, see REGF_SENDER.
ANY_ADDR=${ANY_ADDR:-10.0.99.1}
ANY_R2=${ANY_R2:-10.0.23.2}
ANY_R3=${ANY_R3:-10.0.23.3}
ANY_DR=${ANY_DR:-10.0.1.1}
ANY_GROUP=${ANY_GROUP:-225.1.2.4}
ANY_REFRESH=${ANY_REFRESH:-240}
# anycast, the last two steps: the register-sg-limit R2 runs the whole
# scenario with, low enough for a handful of Registers to reach it; the
# group and source of the burst the copy budget is tested with, and how
# many Registers are in it, more than ANYCAST_RP_COPY_RATE (src/pimd.h) in
# one second; and the group the limit is tested on
ANY_SG_LIMIT=${ANY_SG_LIMIT:-4}
ANY_BURST_GROUP=${ANY_BURST_GROUP:-225.1.2.5}
ANY_BURST_SRC=${ANY_BURST_SRC:-10.0.1.90}
ANY_BURST=${ANY_BURST:-600}
ANY_LIMIT_GROUP=${ANY_LIMIT_GROUP:-225.1.2.6}
# anycast-dr: R1's member address, its end of the R1-R2 link.  R3 is
# member $ANY_R3 as in anycast.
ANYDR_R1=${ANYDR_R1:-10.0.12.1}
# anycast-dr, the last step: the (S,G) R1 holds without registering it
ANYDR_STOP_GROUP=${ANYDR_STOP_GROUP:-225.1.2.7}
ANYDR_STOP_SRC=${ANYDR_STOP_SRC:-10.0.3.90}

# crafted: the addresses and the one bad byte that scenario is built on.
#
# $CRAFT_ADDR is a second address on ED1's interface, so the sender can be
# a stranger on the link at the same time as $SRC_ADDR is a neighbour on
# it; $R1_LAN_ADDR is what R1 answers to there, which a Join has to name as
# its upstream neighbour to be acted on rather than merely overheard.
#
# $CRAFT_BADLEN is above 32 and below 256, which is every value the byte can
# hold that no IPv4 address has.  200 rather than 33 because the two fail
# differently once the shift wraps -- 33 yielded 128.0.0.0/1 and 200
# yielded 224.0.0.0/8 -- and neither is more wrong than the other.
#
# $CRAFT_PRIO has to beat R2's BSR priority of 1, or the crafted Bootstrap
# is dropped as less preferred before it reaches anything under test.
CRAFT_ADDR=${CRAFT_ADDR:-10.0.1.99}
# A secondary address the Hello Address List steps have ED1 advertise.  It
# is never configured anywhere: the option is what is under test, not the
# address.
CRAFT_SECADDR=${CRAFT_SECADDR:-10.0.1.77}
CRAFT_SRC=${CRAFT_SRC:-10.0.1.10}
R1_LAN_ADDR=${R1_LAN_ADDR:-10.0.1.1}
CRAFT_BADLEN=${CRAFT_BADLEN:-200}
CRAFT_PRIO=${CRAFT_PRIO:-200}

# A source R1 has a route to but no interface on, so an (S,G) Join names
# something it can build state for; and how long the holdtime assertion
# watches, three TIMER_INTERVALs, which is long enough that a timer that
# ages has visibly moved.
CRAFT_FAR_SRC=${CRAFT_FAR_SRC:-10.0.3.10}

# crafted, the Join suppression steps.  $SUPP_ADDR is a second router on
# R1's link to R2, $R1_UP_ADDR R1's own end of that link.  $SUPP_WINDOW has
# to hold at least two of R1's periodic Joins, $SUPP_PERIOD apart, so an R1
# that does not suppress is seen to send; $SUPP_EVERY is under the smallest
# t_suppressed, 66s, so one that does never runs out.  $SUPP_SHORT_WAIT is
# the longest t_suppressed, 84s, left over from step 5, plus a tick.
SUPP_ADDR=${SUPP_ADDR:-10.0.12.9}
R1_UP_ADDR=${R1_UP_ADDR:-10.0.12.1}

# rpt: the contested elections.  R1 takes the BSR with the higher priority
# of the two and loses the RP with the higher number of the two, so the BSR
# is $R1_UP_ADDR and the RP stays $RP_ADDR.
BSR_PRIO=${BSR_PRIO:-12}
CRP_LOSER_PRIO=${CRP_LOSER_PRIO:-30}

# rpt: the group nobody has joined when its stream starts, and how long
# after the first packet the receiver joins it -- the ordering of
# https://github.com/troglobit/pimd/issues/192
LATE_GROUP=${LATE_GROUP:-225.1.2.9}
LATE_DELAY=${LATE_DELAY:-2}
SUPP_GROUP=${SUPP_GROUP:-225.1.4.4}
SUPP_PERIOD=${SUPP_PERIOD:-60}
SUPP_WINDOW=${SUPP_WINDOW:-140}
SUPP_EVERY=${SUPP_EVERY:-20}
SUPP_SHORT_HOLD=${SUPP_SHORT_HOLD:-10}
SUPP_SHORT_WAIT=${SUPP_SHORT_WAIT:-100}

# crafted, the timing steps.  $OVR_WINDOW is the J/P_Override_Interval R2
# grants on defaults, 0.5s Propagation_Delay plus 2.5s Override_Interval, in
# which R1's override Join has to reach it.  $HELLO_DELAY is
# Triggered_Hello_Delay, with $HELLO_SLACK for the scheduling on top, and an
# answer later than $HELLO_PROMPT is one that was not sent at once.
OVR_TRIALS=${OVR_TRIALS:-6}
OVR_WINDOW=${OVR_WINDOW:-3000}
HELLO_TRIALS=${HELLO_TRIALS:-5}
HELLO_DELAY=${HELLO_DELAY:-5000}
HELLO_SLACK=${HELLO_SLACK:-500}
HELLO_PROMPT=${HELLO_PROMPT:-500}
# And the Prune-Pending Timer: $PP_WINDOW is J/P_Override_Interval again,
# which a PruneEcho may not come before by more than $PP_EARLY, the log's
# own rounding, nor after by more than $PP_LATE.
PP_TRIALS=${PP_TRIALS:-3}
PP_GROUP=${PP_GROUP:-225.1.5.5}
PP_WINDOW=${PP_WINDOW:-3000}
PP_EARLY=${PP_EARLY:-50}
PP_LATE=${PP_LATE:-500}

# crafted, the (S,G,rpt) steps, M1 of doc/rfc7761-compliance.md.  A group of
# their own each, so no state an earlier step left decides an answer:
# $RPT_SG_GROUP carries an (S,G) Join and nothing else, $RPT_GROUP a (*,G)
# Join that the source $CRAFT_FAR_SRC is pruned off.  $RPT_SETTLE is how
# long after a Prune the Prune-Pending Timer has certainly run out,
# $PP_WINDOW plus a tick, and $RPT_PROMPT the most a check made "right
# after" a message may lag it and still be inside that window.
RPT_SG_GROUP=${RPT_SG_GROUP:-225.1.6.6}
RPT_GROUP=${RPT_GROUP:-225.1.7.7}
RPT_SETTLE=${RPT_SETTLE:-6}
RPT_PROMPT=${RPT_PROMPT:-2}
RPT_OVR_TRIALS=${RPT_OVR_TRIALS:-3}

# crafted, step 13b: the rpt-prune-limit R1 runs with, low enough for one
# Prune to fill, and the sources it is filled with.  They sit beside
# $CRAFT_FAR_SRC so that R1 has a route to them, which an entry needs, and
# $RPT_LIMIT_HOLD is short enough that they are gone before anything later
# could meet them.
RPT_LIMIT=${RPT_LIMIT:-8}
RPT_LIMIT_NET=${RPT_LIMIT_NET:-10.0.3}
RPT_LIMIT_HOLD=${RPT_LIMIT_HOLD:-90}

# The longer group range of R2 in doc/rfc7761-compliance.md, covering $GROUP
# and not $CRAFT_OUT_GROUP, which both sit in the 224.0.0.0/4 R2 advertises
CRAFT_RANGE=${CRAFT_RANGE:-225.1.2.0}
CRAFT_RANGE_LEN=${CRAFT_RANGE_LEN:-24}
CRAFT_OUT_GROUP=${CRAFT_OUT_GROUP:-225.1.3.3}

# A group in the default SSM range, and the RP config.c invents for such a
# range: a link-local address that leads nowhere, which is what an SSM group
# resolves to and therefore the only address a (*,G) Join for one could name
# and be believed.  See mrt.c, which installs it.
SSM_GROUP=${SSM_GROUP:-232.1.1.1}
SSM_VIRTUAL_RP=${SSM_VIRTUAL_RP:-169.254.0.1}

# Packets the ssm scenario sends from its first hop router's LAN, only to
# give that router an (S,G) to look at
SSM_PKTS=${SSM_PKTS:-6}

# crafted, the No-Forward assertions.  $NOFWD_BSR is deliberately off every
# subnet the lab builds and out of every static route it installs, so the
# RPF check toward it cannot pass and the bit is the only thing that can
# let the message in.  The two ranges are separate so the second assertion
# is not reading what the first installed.
NOFWD_BSR=${NOFWD_BSR:-10.0.9.9}
NOFWD_RANGE=${NOFWD_RANGE:-239.1.0.0}
NOFWD_RANGE2=${NOFWD_RANGE2:-239.2.0.0}

# The second assertion's BSR has to beat the first one's, or the message is
# dropped as less preferred before anything under test is reached: the two
# share a priority and $NOFWD_BSR is the higher address.
NOFWD_PRIO=${NOFWD_PRIO:-250}

# A third address on ED1's interface, on the same subnet as the other two
# and named by no accept-nbr-from, which is what makes it the one the
# filter has to refuse
DENIED_ADDR=${DENIED_ADDR:-10.0.1.88}
# fuzz: how many mutants of each message type, how many bytes of each are
# flipped, and what the flips are drawn from.  The seed is fixed rather than
# random on purpose: a scenario that fails has to be a scenario somebody can
# run again, and pimsend draws the same packets from the same seed on either
# system.  Raise FUZZ_COUNT for a hunt (and vary FUZZ_SEED, one run of a
# fixed seed explores exactly one set of packets however long it is);
# these defaults are a regression test, seconds long.
#
# Every type pimsend can build: the six that go to ALL-PIM-ROUTERS and the
# two that are unicast to the router.
FUZZ_COUNT=${FUZZ_COUNT:-500}
FUZZ_FLIPS=${FUZZ_FLIPS:-3}
FUZZ_SEED=${FUZZ_SEED:-1}
FUZZ_TYPES=${FUZZ_TYPES:-"hello join prune assert bootstrap candrp register regstop"}
# How long R1 is given to learn the RP set before the flood, the bootstrap
# interval in the generated configs being 10s
FUZZ_RP_WAIT=${FUZZ_RP_WAIT:-90}
# The group range R2 advertises an RP for, and the one step 6 reads back
FUZZ_RP_RANGE=${FUZZ_RP_RANGE:-224.0.0.0/4}

CRAFT_HOLD=${CRAFT_HOLD:-15}

# How long R1's dynamic RP may take to age out once the BSR is killed.  The
# cand-RP holdtime is twice r2.conf's advertisement interval of 10s, and the
# bootstrap timeout is longer, so this is the bootstrap timer's business.
CRAFT_RP_WAIT=${CRAFT_RP_WAIT:-180}

# register-filter: the two "register-accept-from" prefixes R2 is given, in
# the order it gets them, and the address R1 actually registers from.
#
# $REGF_DENY covers R1's address on the link to the RP and not the one it
# registers from, and picking it that way is the point.  send_pim_register()
# (src/pim_proto.c) sources the Register from the VIF the *source* is
# directly connected to, so what the RP matches against its list is
# $REGF_SENDER, on the sender's LAN, and not the 10.0.12.1 that the
# neighbour table of every router on the path shows.  An operator who reads
# the two addresses the other way round writes a filter that denies nothing
# and one that denies everything, and this scenario is shaped so that either
# mistake in pimd shows up as a failure rather than as a run that passes.
REGF_DENY=${REGF_DENY:-10.0.12.0/24}
REGF_ACCEPT=${REGF_ACCEPT:-10.0.1.0/24}
REGF_SENDER=${REGF_SENDER:-10.0.1.1}

# Packets ED1 sends in each half, one per second.  Nothing here has to
# outlive a timer, so this is only long enough to leave no doubt that the
# stream ran while the filter was in force.
REGF_PKTS=${REGF_PKTS:-20}
# Longer than Register_Suppression_Time can hold R1 off, 90 seconds, see
# step 9 of register-filter
REGF_SUPP_WAIT=${REGF_SUPP_WAIT:-100}

# ifgone: the link that is destroyed under R1, named from both ends
# because an epair can only be destroyed from the jail that owns an end,
# and both ends of this one live in jails.  IFGONE_KEPT is the address on
# R1's other interface, the one the register VIF has to fall back to.
IFGONE_IF=${IFGONE_IF:-${EP}101b}
IFGONE_PEER_IF=${IFGONE_PEER_IF:-${EP}101a}
IFGONE_ADDR=${IFGONE_ADDR:-10.0.1.1}
IFGONE_KEPT=${IFGONE_KEPT:-10.0.12.1}
IFGONE_KEPT_IF=${IFGONE_KEPT_IF:-${EP}112a}

# The two interfaces that turn up once $IFGONE_IF is gone, to ask who owns
# its subnet now.  $IFGONE_NEW_IF carries another address out of
# $IFGONE_ADDR's subnet, which is that address failing over to a second NIC
# or the VLAN rebuilt under another name, and it has to get a VIF: the VIF
# that used to own the subnet belongs to an interface the kernel no longer
# has.  $IFGONE_DUP_IF is the control beside it, created once $IFGONE_NEW_IF
# has been taken down rather than destroyed -- the VIF owning the subnet is
# then out of service too, but its interface is still there, still
# addressed, and only waiting to come back up, so this one has to be
# refused.  Both far ends stay on the host, unaddressed: nothing has to
# answer on either, the question is only which of them pimd gives a VIF.
IFGONE_NEW_EP=${IFGONE_NEW_EP:-${EP}191}
IFGONE_NEW_IF=${IFGONE_NEW_IF:-${IFGONE_NEW_EP}a}
IFGONE_NEW_ADDR=${IFGONE_NEW_ADDR:-10.0.1.9}
IFGONE_DUP_EP=${IFGONE_DUP_EP:-${EP}192}
IFGONE_DUP_IF=${IFGONE_DUP_IF:-${IFGONE_DUP_EP}a}
IFGONE_DUP_ADDR=${IFGONE_DUP_ADDR:-10.0.1.19}
IFGONE_NEW_PREFIX=${IFGONE_NEW_PREFIX:-24}

# How long pimd may take to act on either, for IFNEW_WAIT's reason: the
# kernel's notification reaches it in about a second, the periodic rescan
# every 60s is only the floor under that.
IFGONE_NEW_WAIT=${IFGONE_NEW_WAIT:-30}

# Both are built by check_ifgone() rather than with the boxes, so stop() is
# told about them here instead of with the rest.
ALL_EPAIRS="$ALL_EPAIRS $IFGONE_NEW_EP $IFGONE_DUP_EP"

# renumber: R2's address on the R1 link moves, inside its own subnet, which
# is what an interface renumbered under a running pimd looks like -- a DHCP
# lease that changed, an ifconfig edit, a failover address moved.  Staying
# inside the subnet keeps the change to the one thing being tested: only the
# routes naming it as a gateway have to follow it.  R2 is the router in the
# middle, so its other VIF stays put and shows the restart was confined to
# the interface that moved.
# R2's link to R1 is not the one to move: it is renamed Epair112b on purpose
# (see renames()) and r2.conf names it in bsr-candidate and rp-candidate, so
# renumbering it would move the RP address as well and the scenario would be
# about something else.  The R3 link carries no such role.
RENUM_IF=${RENUM_IF:-${EP}123a}
RENUM_OLD=${RENUM_OLD:-10.0.23.2}
RENUM_NEW=${RENUM_NEW:-10.0.23.22}
RENUM_PEER=${RENUM_PEER:-r3}
RENUM_KEPT=${RENUM_KEPT:-10.0.12.1}
RENUM_KEPT_IF=${RENUM_KEPT_IF:-${EPU}112b}

# The groups pimd joins on every link it runs PIM on: ALL-PIM-ROUTERS on
# the PIM socket, ALL-ROUTERS and the IGMPv3 report group on the IGMP one.
# Without them there is no Hello, no neighbour, no Join and no report.
#
# ifgone and renumber both take an interface out from under a running pimd,
# which is when the leave issued for it can name an address the kernel can
# no longer place and take another interface's membership instead.  Which
# one it takes is the first in that *socket's* list, so the two sockets can
# lose groups on different interfaces and all three have to be asked for.
PIM_GROUPS=${PIM_GROUPS:-"224.0.0.13 224.0.0.2 224.0.0.22"}

# How long to watch them for.  Measured on the losing side: pimd acted on
# the address six seconds after it moved, one TIMER_INTERVAL, and the
# kernel had the membership off the other interface a second after that.
GROUP_WATCH=${GROUP_WATCH:-20}

# gif-tunnel: the tunnel R1 and R3 build over R2.  The inner prefix is a
# /24 on a point-to-point link on purpose, see the header.
GIF_IF=gif0
GIF_R1=172.16.0.1
GIF_R3=172.16.0.2
GIF_MASK=255.255.255.0

die() { echo -n "EXIT: " >&2; echo "$@" >&2; exit 1; }
print() { printf "\033[7m>> %-76s\033[0m\n" "$1"; }
dprint() { printf "\033[2m%-76s\033[0m\n" "$1"; }

FAILED=0
XFAILED=0
ok()   { printf "  \033[32mok\033[0m    %s\n" "$1"; }
fail() { printf "  \033[31mFAIL\033[0m  %s\n" "$1"; FAILED=$((FAILED + 1)); }
skip() { printf "  \033[33mSKIP\033[0m  %s\n" "$1"; }

# A behaviour that is wrong but known to be wrong: pimd deviates from the
# spec here, the scenario reproduces it on purpose, and the run is not red
# because of it.  It is still printed on every run, and the moment pimd
# starts doing the right thing the assertion that guards it turns into an
# ok and says so, which is the point of writing it down rather than
# leaving the case untested.
xfail() { printf "  \033[33mKNOWN\033[0m %s\n" "$1"; XFAILED=$((XFAILED + 1)); }

# The verdict a scenario ends on, and its exit status.  Every check_*()
# has to print one: "run all" is a long log, and a scenario that stops
# after its last assertion without saying anything reads like one that
# merely got quieter.  ssm, ssm-range, ifgone and renumber each ended on a
# bare "[ $FAILED -eq 0 ] || return 1" until this existed, so the only sign
# that one of them had failed was the exit status of the whole run.
#
# The scenarios that dump state on failure still print their own line
# before the dump, which has to come between the verdict and the return.
result() {
	echo
	if [ "$FAILED" -ne 0 ]; then
		print "RESULT: FAIL ($FAILED assertion(s))"
		return 1
	fi

	if [ "$XFAILED" -gt 0 ]; then
		print "RESULT: PASS ($XFAILED known deviation(s), see above)"
	else
		print "RESULT: PASS"
	fi

	return 0
}

usage() {
	cat <<-EOF
	usage: $0 [-s SLOT] [-j JOBS] start|check|run [scenario...] | run all | stop

	  start [scenario]  build the lab and start pimd on its routers
	  check [scenario]  run the assertions against a lab that is up
	  run   [scenario]  start, check, stop; exit 0 if every assertion passed
	  run   s1 s2 ...   those scenarios
	  run   all         every scenario below
	  stop              tear this slot's lab down

	  -s SLOT  which lab this is, 0 to 31, default 0.  A slot names its
	           jails, its links and its work directory apart from every
	           other, so one machine can hold several labs at once.
	  -j JOBS  how many scenarios to run at the same time, in slots
	           $SLOT upwards, one slot each.  Default 1, one after another.

	Scenarios: $(echo $SCENARIOS)
	EOF
}

# Three scenarios, one topology: it is the only one in this file with more
# than one PIM router on a link, so anything about an election has to be
# built on it.  shared-lan and shared-lan-spt differ in whether the last hop
# router is allowed onto the shortest path tree, and therefore in which of
# the two contenders the spec says must win the assert; assert-recover takes
# shared-lan's answer as its starting point and goes after the two ways a
# router leaves the assert state again.
is_shared_lan() {
	case $SCENARIO in
	shared-lan|shared-lan-spt|assert-recover) return 0 ;;
	esac

	return 1
}

set_scenario() {
	case ${1:-$SCENARIO} in
	rpt|solo|privsep|keepalive|rp-lasthop|rp-offpath|gif-tunnel|gif-tunnel-staticrp|shared-lan|shared-lan-spt|ssm|ssm-range|alias|ifnew|ifgone|renumber|assert-recover|register-filter|crafted|fuzz|static-rp|anycast|anycast-dr)
		SCENARIO=${1:-$SCENARIO} ;;
	*) usage; exit 2 ;;
	esac

	# The shared segment scenarios have a topology of their own, five
	# routers over two bridges instead of three in a row.  Every other
	# scenario has to put the three router one back, or it inherits
	# whatever "run all" left behind: the routers pimd is started on and
	# asserted against are read from these.
	if is_shared_lan; then
		BOXES=$SHARED_BOXES
		ROUTERS=$SHARED_ROUTERS
		EPAIRS="${EP}101 ${EP}112 $SHARED_EPAIRS"
		ED2_IF=${EP}510b
		# assert-recover needs a DR address it can renumber
		# downwards from, see AR_DR_ADDR
		if [ "$SCENARIO" = assert-recover ]; then
			SL_DR_ADDR=$AR_DR_ADDR
		else
			SL_DR_ADDR=$SL_DR_ADDR_DEFAULT
		fi
	elif [ "$SCENARIO" = solo ]; then
		BOXES=$SOLO_BOXES
		ROUTERS=$SOLO_ROUTERS
		EPAIRS=$SOLO_EPAIRS
		ED2_IF=$SOLO_ED2_IF
	elif [ "$SCENARIO" = rp-offpath ]; then
		BOXES=$DEFAULT_BOXES
		ROUTERS=$DEFAULT_ROUTERS
		EPAIRS=$OFFPATH_EPAIRS
		ED2_IF=$DEFAULT_ED2_IF
	else
		BOXES=$DEFAULT_BOXES
		ROUTERS=$DEFAULT_ROUTERS
		EPAIRS=$DEFAULT_EPAIRS
		ED2_IF=$DEFAULT_ED2_IF
	fi

	# What crafted asserts on is what the Join/Prune parser refuses, and
	# every one of those lines sits behind IF_DEBUG(DEBUG_PIM_JOIN_PRUNE)
	# (src/pim_proto.c) -- as does the one that says a well-formed Join
	# was accepted, so without this the scenario's positive control fails
	# beside its negative ones and says nothing about either.  The rest of
	# the file does not ask for pim_jp, which is the noisiest subsystem
	# here: every router logs every Join it sends and receives, once per
	# Join/Prune period, for the whole run.  pim_hello is here for the
	# same reason: the line that says a Hello was refused by
	# accept-nbr-from sits behind IF_DEBUG(DEBUG_PIM_HELLO).
	if [ "$SCENARIO" = crafted ] || [ "$SCENARIO" = fuzz ]; then
		DEBUG="$DEBUG_DEFAULT,pim_jp,pim_hello"
	else
		DEBUG=$DEBUG_DEFAULT
	fi

	# Extra arguments for every pimd this scenario starts.  Only privsep
	# sets it, for the --no-privsep control it ends on, and it is put
	# back here rather than only there because "run all" without -j walks
	# every scenario in one shell.
	#
	# Under COVERAGE=yes that default is --no-privsep instead, the
	# separated child being unable to write a .gcda at all -- except for
	# the privsep scenario, where the separation is the thing under test
	# and starting it unseparated would assert nothing.
	if [ "$COVERAGE" = yes ] && [ "$SCENARIO" != privsep ]; then
		PIMD_ARGS="--no-privsep"
	else
		PIMD_ARGS=
	fi

	# gif-tunnel-staticrp copies the issue down to the addresses: the
	# KNX/IP group its reporters run, and the 224.0.0.0/16 rp-address
	# mask their pimd.conf uses, which only just covers that group.
	# 225.1.2.3, the group every other scenario uses, would fall
	# outside it and never resolve to an RP at all.
	if [ "$SCENARIO" = gif-tunnel-staticrp ]; then
		GROUP=${STATICRP_GROUP:-224.0.23.12}
	elif [ "$SCENARIO" = ssm ]; then
		# 232.0.0.0/8 is the default SSM range, and the only range
		# where pimd keeps a source list per group at all
		GROUP=${SSM_GROUP:-232.1.1.1}
	elif [ "$SCENARIO" = ssm-range ]; then
		# Inside the range r3.conf configures, and outside the
		# default one it replaces
		GROUP=$SSMR_GROUP
	else
		GROUP=$GROUP_DEFAULT
	fi

	# alias: the sender moves onto the aliased subnet, which is the
	# whole scenario.  Every assertion keyed on the source, and the
	# pimd.conf comments generated for it, read this.
	if [ "$SCENARIO" = alias ]; then
		SRC_ADDR=$ALIAS_SRC_ADDR
	else
		SRC_ADDR=$SRC_ADDR_DEFAULT
	fi
}

# Interfaces each box owns, "a" and "b" ends of the epairs above
ifaces() {
	if is_shared_lan; then
		# The bridged segments hand out "b" ends only, their "a" ends
		# stay on the host in $BR_UPSTREAM / $BR_RECEIVER
		case $1 in
		ed1) echo "${EP}101a" ;;
		r1)  echo "${EP}101b ${EP}112a" ;;
		r2)  echo "${EP}112b ${EP}223b" ;;
		r3)  echo "${EP}323b ${EP}303b" ;;
		r4)  echo "${EP}423b ${EP}403b" ;;
		r5)  echo "${EP}503b ${EP}510a" ;;
		ed2) echo "${EP}510b" ;;
		ed3) echo "${EP}603b" ;;
		esac
		return
	fi

	if [ "$SCENARIO" = solo ]; then
		case $1 in
		ed1) echo "${EP}101a" ;;
		r1)  echo "${EP}101b ${EP}104a" ;;
		ed2) echo "${EP}104b" ;;
		esac
		return
	fi

	if [ "$SCENARIO" = rp-offpath ]; then
		case $1 in
		ed1) echo "${EP}101a" ;;
		r1)  echo "${EP}101b ${EP}112a $OFFPATH_R1_IF" ;;
		r2)  echo "${EP}112b ${EP}123a" ;;
		r3)  echo "${EP}123b ${EP}203a $OFFPATH_R3_IF" ;;
		ed2) echo "${EP}203b" ;;
		esac
		return
	fi

	case $1 in
	ed1) echo "${EP}101a" ;;
	r1)  echo "${EP}101b ${EP}112a" ;;
	r2)  echo "${EP}112b ${EP}123a" ;;
	r3)  echo "${EP}123b ${EP}203a" ;;
	ed2) echo "${EP}203b" ;;
	esac
}

# Interfaces renamed once the jail owns them, "<old> <new>" pairs.
#
# R2's link to R1 deliberately carries an uppercase letter, and r2.conf
# then names that interface in its bsr-candidate and rp-candidate lines.
# pimd lowercases every token it reads from the .conf (next_word() in
# src/config.c), while the kernel keeps the name as it is, so a
# case-sensitive lookup silently fails to resolve the interface: pimd
# falls back to the highest active address and advertises the wrong RP.
# Assertion 3 catches that, because it demands the RP be $RP_ADDR rather
# than whatever address happens to be numerically highest.
# See https://github.com/troglobit/pimd/pull/252.
renames() {
	case $1 in
	r2) echo "${EP}112b ${EPU}112b" ;;
	*)  echo "" ;;
	esac
}

# "<interface> <address>/<prefixlen>" pairs to configure per box
addrs() {
	if is_shared_lan; then
		case $1 in
		ed1) echo "${EP}101a 10.0.1.10/24" ;;
		r1)  echo "${EP}101b 10.0.1.1/24 ${EP}112a 10.0.12.1/24" ;;
		r2)  echo "${EPU}112b 10.0.12.2/24 ${EP}223b 10.0.23.2/24" ;;
		r3)  echo "${EP}323b 10.0.23.3/24 ${EP}303b $SL_R3_ADDR/24" ;;
		r4)  echo "${EP}423b 10.0.23.4/24 ${EP}403b $SL_DR_ADDR/24" ;;
		r5)  echo "${EP}503b $SL_QUERIER_ADDR/24 ${EP}510a 10.0.5.1/24" ;;
		ed2) echo "${EP}510b 10.0.5.10/24" ;;
		ed3) echo "${EP}603b $SL_ED3_ADDR/24" ;;
		esac
		return
	fi

	if [ "$SCENARIO" = rp-offpath ]; then
		case $1 in
		ed1) echo "${EP}101a 10.0.1.10/24" ;;
		r1)  echo "${EP}101b 10.0.1.1/24 ${EP}112a 10.0.12.1/24 $OFFPATH_R1_IF $OFFPATH_R1_ADDR/24" ;;
		r2)  echo "${EPU}112b 10.0.12.2/24 ${EP}123a 10.0.23.2/24" ;;
		r3)  echo "${EP}123b 10.0.23.3/24 ${EP}203a 10.0.3.1/24 $OFFPATH_R3_IF $OFFPATH_R3_ADDR/24" ;;
		ed2) echo "${EP}203b 10.0.3.10/24" ;;
		esac
		return
	fi

	if [ "$SCENARIO" = solo ]; then
		case $1 in
		ed1) echo "${EP}101a 10.0.1.10/24" ;;
		r1)  echo "${EP}101b 10.0.1.1/24 ${EP}104a 10.0.4.1/24" ;;
		ed2) echo "${EP}104b $SOLO_RCV_ADDR/24" ;;
		esac
		return
	fi

	# anycast: the RP address is the only address lo0 has in R2 and R3,
	# so it is lo0's primary, the one pimd makes a VIF of
	if [ "$SCENARIO" = anycast-dr ]; then
		case $1 in
		ed1) echo "${EP}101a 10.0.1.10/24" ;;
		r1)  echo "${EP}101b 10.0.1.1/24 ${EP}112a 10.0.12.1/24 $LOOPBACK_IF $ANY_ADDR/32" ;;
		r2)  echo "${EPU}112b 10.0.12.2/24 ${EP}123a 10.0.23.2/24" ;;
		r3)  echo "${EP}123b 10.0.23.3/24 ${EP}203a 10.0.3.1/24 $LOOPBACK_IF $ANY_ADDR/32" ;;
		ed2) echo "${EP}203b 10.0.3.10/24" ;;
		esac
		return
	fi

	if [ "$SCENARIO" = anycast ]; then
		case $1 in
		ed1) echo "${EP}101a 10.0.1.10/24" ;;
		r1)  echo "${EP}101b 10.0.1.1/24 ${EP}112a 10.0.12.1/24" ;;
		r2)  echo "${EPU}112b 10.0.12.2/24 ${EP}123a 10.0.23.2/24 $LOOPBACK_IF $ANY_ADDR/32" ;;
		r3)  echo "${EP}123b 10.0.23.3/24 ${EP}203a 10.0.3.1/24 $LOOPBACK_IF $ANY_ADDR/32" ;;
		ed2) echo "${EP}203b 10.0.3.10/24" ;;
		esac
		return
	fi

	if [ "$SCENARIO" = alias ]; then
		case $1 in
		ed1) echo "${EP}101a $ALIAS_SRC_ADDR/24" ;;
		r1)  echo "${EP}101b 10.0.1.1/24 ${EP}112a 10.0.12.1/24" ;;
		r2)  echo "${EPU}112b 10.0.12.2/24 ${EP}123a 10.0.23.2/24" ;;
		r3)  echo "${EP}123b 10.0.23.3/24 ${EP}203a 10.0.3.1/24" ;;
		ed2) echo "${EP}203b 10.0.3.10/24" ;;
		esac
		return
	fi

	case $1 in
	ed1) echo "${EP}101a 10.0.1.10/24" ;;
	r1)  echo "${EP}101b 10.0.1.1/24 ${EP}112a 10.0.12.1/24" ;;
	r2)  echo "${EPU}112b 10.0.12.2/24 ${EP}123a 10.0.23.2/24" ;;
	r3)  echo "${EP}123b 10.0.23.3/24 ${EP}203a 10.0.3.1/24" ;;
	ed2) echo "${EP}203b 10.0.3.10/24" ;;
	esac
}

# Extra addresses to add on an interface that addrs() already gave one,
# "<interface> <address>/<prefixlen>" pairs.  These are what "ifconfig
# alias" makes: a second address on the same interface, which the kernel
# hands to getifaddrs() as another entry with the same ifa_name, and which
# pimd cannot give a VIF of its own.
#
# Only the alias scenario has any.  The order matters: addrs() runs first,
# so the address the vif ends up with is 10.0.1.1 and the aliased subnet
# is the one that has to survive as an altnet.
aliases() {
	[ "$SCENARIO" = alias ] || return 0

	case $1 in
	r1) echo "$ALIAS_IF $ALIAS_ADDR/24 $ALIAS_UP_IF $ALIAS_UP_ADDR/24" ;;
	esac
}

# Routers that run pimd.  gif-tunnel leaves R2 as a plain unicast transit
# router with no pimd at all, which is the whole point: it stands in for
# the network between two VPN endpoints, and PIM only ever meets it as
# the carrier of the gif outer packets.
pim_routers() {
	case $SCENARIO in
	gif-tunnel|gif-tunnel-staticrp) echo "r1 r3" ;;
	*)                              echo "$ROUTERS" ;;
	esac
}

# gif tunnels to build inside a box, as
# "<ifname> <outer-local> <outer-remote> <inner-local> <inner-remote>".
# Only gif-tunnel has any; the outer addresses are the ones R2 already
# routes between, so the tunnel needs no extra plumbing of its own.
tunnels() {
	case $SCENARIO in
	gif-tunnel|gif-tunnel-staticrp) ;;
	*) return 0 ;;
	esac

	case $1 in
	r1) echo "$GIF_IF 10.0.12.1 10.0.23.3 $GIF_R1 $GIF_R3" ;;
	r3) echo "$GIF_IF 10.0.23.3 10.0.12.1 $GIF_R3 $GIF_R1" ;;
	esac
}

# Static unicast routes, "<destination> <gateway>" pairs.  pimd needs a
# unicast RPF answer for every source and for the RP.
routes() {
	# gif-tunnel: R1 and R3 reach each other's LAN through the tunnel,
	# so that is where their RPF lookups land, while the underlay
	# routes stay put to carry the gif outer packets through R2.
	case $SCENARIO in
	gif-tunnel|gif-tunnel-staticrp)
		case $1 in
		ed1) echo "default 10.0.1.1" ;;
		r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 $GIF_R3" ;;
		r2)  echo "10.0.1.0/24 10.0.12.1 10.0.3.0/24 10.0.23.3" ;;
		r3)  echo "10.0.12.0/24 10.0.23.2 10.0.1.0/24 $GIF_R1" ;;
		ed2) echo "default 10.0.3.1" ;;
		esac
		return ;;
	solo)
		# Both LANs are R1's own, so the end devices need nothing but
		# a way off theirs and R1 needs no route at all
		case $1 in
		ed1) echo "default 10.0.1.1" ;;
		ed2) echo "default 10.0.4.1" ;;
		esac
		return ;;
	rp-offpath)
		# The triangle: R1 and R3 reach each other directly, so the
		# RPF answer for the source on the last hop router, and for
		# the receiver LAN on the first hop one, is the direct link.
		# Only the RP is reached the long way around, over R2, which
		# is the whole shape of the scenario: the shared tree and the
		# shortest path tree do not share an interface anywhere.
		case $1 in
		ed1) echo "default 10.0.1.1" ;;
		r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 $OFFPATH_R3_ADDR" ;;
		r2)  echo "10.0.1.0/24 10.0.12.1 10.0.3.0/24 10.0.23.3 10.0.13.0/24 10.0.12.1" ;;
		r3)  echo "10.0.12.0/24 10.0.23.2 10.0.1.0/24 $OFFPATH_R1_ADDR" ;;
		ed2) echo "default 10.0.3.1" ;;
		esac
		return ;;
	shared-lan|shared-lan-spt|assert-recover)
		# R5 reaches the source and the RP through R3, which is what
		# makes this scenario work: its Join names R3 as the upstream
		# router, and receive_pim_join_prune() (src/pim_proto.c) only
		# lets the router named in the Join add the oif, everyone else
		# on the LAN uses it for suppression.  R3 therefore forwards
		# because of R5's Join and R4 because of ED3's IGMP report,
		# and the LAN has the two forwarders an assert needs.
		#
		# R2 reaches everything behind the LAN through R4, so the
		# reverse direction (ED2's mping replies climbing back to the
		# RP) uses the same router as the forward one.  Pointed at R3
		# instead, the RP would pull the replies through the router
		# that loses the assert and the two directions would settle
		# independently - legal, but one more thing to explain when a
		# count comes out wrong.
		case $1 in
		ed1) echo "default 10.0.1.1" ;;
		r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2 10.0.5.0/24 10.0.12.2" ;;
		r2)  echo "10.0.1.0/24 10.0.12.1 10.0.3.0/24 10.0.23.4 10.0.5.0/24 10.0.23.4" ;;
		r3)  echo "10.0.1.0/24 10.0.23.2 10.0.12.0/24 10.0.23.2 10.0.5.0/24 $SL_QUERIER_ADDR" ;;
		r4)  echo "10.0.1.0/24 10.0.23.2 10.0.12.0/24 10.0.23.2 10.0.5.0/24 $SL_QUERIER_ADDR" ;;
		r5)  echo "10.0.1.0/24 $SL_R3_ADDR 10.0.12.0/24 $SL_R3_ADDR 10.0.23.0/24 $SL_R3_ADDR" ;;
		ed2) echo "default 10.0.5.1" ;;
		ed3) echo "default $SL_DR_ADDR" ;;
		esac
		return ;;
	anycast-dr)
		# The rpt routes, and R2's route to the RP address, to R1
		case $1 in
		ed1) echo "default 10.0.1.1" ;;
		r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2" ;;
		r2)  echo "10.0.1.0/24 10.0.12.1 10.0.3.0/24 10.0.23.3 $ANY_ADDR/32 10.0.12.1" ;;
		r3)  echo "10.0.1.0/24 10.0.23.2 10.0.12.0/24 10.0.23.2" ;;
		ed2) echo "default 10.0.3.1" ;;
		esac
		return ;;
	anycast)
		# The rpt routes, and R1's route to the RP address, which is
		# what makes R2 the member it registers to.  R2 and R3 hold the
		# address themselves and need none.
		case $1 in
		ed1) echo "default 10.0.1.1" ;;
		r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2 $ANY_ADDR/32 10.0.12.2" ;;
		r2)  echo "10.0.1.0/24 10.0.12.1 10.0.3.0/24 10.0.23.3" ;;
		r3)  echo "10.0.1.0/24 10.0.23.2 10.0.12.0/24 10.0.23.2" ;;
		ed2) echo "default 10.0.3.1" ;;
		esac
		return ;;
	alias)
		# The sender only lives on the aliased subnet, so that is the
		# prefix the rest of the domain has to route towards R1 and
		# the one every RPF lookup for the source asks about.
		case $1 in
		ed1) echo "default $ALIAS_ADDR" ;;
		r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2" ;;
		r2)  echo "$ALIAS_NET $ALIAS_UP_ADDR 10.0.3.0/24 10.0.23.3" ;;
		r3)  echo "$ALIAS_NET 10.0.23.2 10.0.12.0/24 10.0.23.2" ;;
		ed2) echo "default 10.0.3.1" ;;
		esac
		return ;;
	esac

	case $1 in
	ed1) echo "default 10.0.1.1" ;;
	r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2" ;;
	r2)  echo "10.0.1.0/24 10.0.12.1 10.0.3.0/24 10.0.23.3" ;;
	r3)  echo "10.0.1.0/24 10.0.23.2 10.0.12.0/24 10.0.23.2" ;;
	ed2) echo "default 10.0.3.1" ;;
	esac
}

# "destination gateway metric" triples, applied to routes() output once the
# box has it.  Only the shared LAN needs any: its two contenders reach the
# RP at the same cost, and at one the kernel did not pick, so that step 12
# can better it on either side and watch the assert election follow.  Every
# other route in this file keeps the metric FreeBSD gives a static route.
route_metrics() {
	route_has_metric || return 0
	case $SCENARIO in
	shared-lan|assert-recover)
		case $1 in
		r3|r4) echo "$SL_RP_NET $SL_RP_GW $SL_METRIC_FAR" ;;
		esac
		;;
	esac
}

pimctl() { j=$1; shift; box_run "$j" "$PIMCTL" -u "$WORKDIR/$j.sock" "$@"; }

# Retry a command until it succeeds or $1 seconds have passed.  PIM is
# slow by design (hello 30s, bootstrap 60s; shortened in the configs
# below), so every assertion polls instead of sleeping a fixed amount.
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
	[ -x "$PIMD" ] || die "$PIMD not found, build it first (PIMD_SRC=$PIMD_SRC)"
	[ -x "$PIMCTL" ] || die "$PIMCTL not found, build it first"
	[ -f "$PIMD_SRC/test/mping.c" ] || die "$PIMD_SRC/test/mping.c not found"
	[ -f "$PIMD_SRC/test/igmpv3.c" ] || die "$PIMD_SRC/test/igmpv3.c not found"
	[ -f "$PIMD_SRC/test/pimsend.c" ] || die "$PIMD_SRC/test/pimsend.c not found"
	if [ "$COVERAGE" = yes ]; then
		# Both compilers leave the same runtime behind, gcc's libgcov
		# and clang's profiling runtime sharing the __gcov_ names
		nm "$PIMD" 2>/dev/null | grep -q '__gcov_' || \
			die "COVERAGE=yes, but $PIMD carries no gcov runtime;" \
			    "configure that tree --enable-coverage CFLAGS=\"-O0 -g\""
	fi
	if [ "$SANITIZE" = yes ]; then
		# Every sanitizer leaves its runtime's symbols behind, undefined
		# where it is a library and defined where it is linked in, and
		# nm(1) lists both
		nm "$PIMD" 2>/dev/null | grep -q '__asan_\|__ubsan_' || \
			die "SANITIZE=yes, but $PIMD holds no sanitizer runtime;" \
			    "configure that tree CFLAGS=\"-fsanitize=address,undefined\"" \
			    "LDFLAGS=\"-fsanitize=address,undefined\""
	fi
	backend_check_req
}

# R2 is the only BSR and RP candidate, pinned to its 10.0.12.2 address so
# the RP address does not depend on interface ordering.  The intervals are
# the RFC minimum (10s) rather than the 60s default, and spt-threshold is
# low, so the lab converges in tens of seconds instead of minutes.
# spt-threshold is deliberately left at the pimd default (switch to the
# shortest path tree on the first packet).  Setting it to a non-zero
# packet count instead makes the routers switch away from the shared tree
# in the middle of the measured stream, and the traffic then stalls for
# one Join/Prune period (~60s) before it recovers - real behaviour, but it
# belongs in an SPT-specific test, not in this one.
#
# The keepalive scenario moves both candidacies to R1, so the router that
# is DR for $SRC_ADDR is also the RP for the groups that source sends to.
# It also asks for spt-threshold infinity, like the pimd.conf in issue
# #251, to keep the RP on the shared tree.
write_configs() {
	if [ "$SCENARIO" = keepalive ]; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: DR for $SRC_ADDR *and* RP for the groups it sends to,
		# with room for exactly those groups
		spt-threshold infinity
		local-sg-limit $KEEP_NUM
		bsr-candidate ${EP}101b priority 1 interval 10
		rp-candidate ${EP}101b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		: > "$WORKDIR/r2.conf"
		: > "$WORKDIR/r3.conf"
		return
	fi

	if [ "$SCENARIO" = ssm ]; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for the reported sources
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: bootstrap router and rendezvous point.  Not used by an
		# SSM group, which never has a shared tree, but the domain
		# needs one for pimd to consider itself converged
		bsr-candidate ${EPU}112b priority 1 interval 10
		rp-candidate ${EPU}112b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		# The membership timeout is
		# IGMP_ROBUSTNESS_VARIABLE * igmp_query_interval +
		# IGMP_QUERY_RESPONSE_INTERVAL (src/igmp_proto.c), 385s at the
		# default query interval.  Nothing in this scenario is worth
		# waiting six minutes for, so the interval is cut to 5s and the
		# timeout with it, to $SSM_TIMEOUT.
		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: last hop router for the receiver LAN
		igmp-query-interval $SSM_QUERY_INTERVAL
		EOF
		return
	fi

	if [ "$SCENARIO" = ssm-range ]; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for the reported sources
		ssm-range $SSMR_RANGE
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: bootstrap router and rendezvous point.  It now matters
		# for the groups of the default range as well: those are
		# ordinary any-source groups once the configured range has
		# replaced 232.0.0.0/8, and an any-source group needs an RP.
		ssm-range $SSMR_RANGE
		bsr-candidate ${EPU}112b priority 1 interval 10
		rp-candidate ${EPU}112b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		# The range is the whole scenario, the query interval is cut
		# for the same reason the ssm scenario cuts it.
		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: last hop router for the receiver LAN
		ssm-range $SSMR_RANGE
		igmp-query-interval $SSM_QUERY_INTERVAL
		EOF
		return
	fi

	if [ "$SCENARIO" = crafted ]; then
		# R1 runs with RFC 7761 sec. 6.2's filter on for the whole
		# scenario, which is as much a soak test of it as the
		# assertion below is a test: every other step here has to go
		# on working with one configured.  The two senders are named
		# one address at a time rather than by their subnet, because
		# what the assertion needs is a third address on that same
		# subnet which is not named -- a prefix covering the link
		# would cover it too.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: accepts PIM from the lab's two senders and from R2,
		# and from nobody else on either link
		phyint ${EP}101b accept-nbr-from $SRC_ADDR accept-nbr-from $CRAFT_ADDR
		phyint ${EP}112a accept-nbr-from 10.0.12.0/24
		rpt-prune-limit $RPT_LIMIT
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: bootstrap router and rendezvous point for all of 224.0.0.0/4
		bsr-candidate ${EPU}112b priority 1 interval 10
		rp-candidate ${EPU}112b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: in the domain with nothing to do
		EOF
		return
	fi

	if [ "$SCENARIO" = ifnew ]; then
		# Both phyint lines name an interface that does not exist
		# when pimd reads this file, which is the whole point of
		# them: pimd warns about each once at start-up and has to
		# apply them anyway once the interfaces turn up.
		#
		# "igmpv2" is picked because it is visible from outside
		# ("pimctl show igmp interface" prints the version per
		# interface) and because it changes nothing else: the VIF
		# runs PIM exactly as it would have.  "disable" is the
		# control beside it.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, with phyint lines for
		# two interfaces that appear only once it is running
		phyint $IFNEW_IF igmpv2
		phyint $IFNEW_OFF_IF disable
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: bootstrap router and rendezvous point for all of
		# 224.0.0.0/4, and the far end of the link that appears.  It
		# has no phyint line for it, so its side is what pimd makes
		# of a new interface with nothing configured.
		bsr-candidate ${EPU}112b priority 1 interval 10
		rp-candidate ${EPU}112b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: last hop router for the receiver LAN
		EOF
		return
	fi

	if [ "$SCENARIO" = static-rp ]; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router, no BSR/RP role
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: bootstrap router and rendezvous point for all of
		# 224.0.0.0/4, advertised under the address facing R1
		bsr-candidate ${EPU}112b priority 1 interval 10
		rp-candidate ${EPU}112b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		# One line, and the whole scenario.  No group after the
		# address means 224.0.0.0/4 (src/config.c), the same prefix
		# R2 advertises under, so the configured entry and the
		# learned ones share one grp_mask_t -- which is what let a
		# Bootstrap collect the configured one.
		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: the only router with an RP of its own configuration
		rp-address $STATICRP_ADDR
		EOF
		return
	fi

	if [ "$SCENARIO" = anycast-dr ]; then
		# As in anycast, with the set moved to R1 and R3: R1 is the
		# DR of $SRC_ADDR, and the route R2 has to $ANY_ADDR takes it
		# to R1 as well.  The anycast-rp lines are added by
		# check_anycast_dr() after the control half.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: DR for $SRC_ADDR and holder of $ANY_ADDR on lo0, so the
		# RP of the group its own source sends to
		rp-address $ANY_ADDR
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: no RP role, its route to $ANY_ADDR goes to R1
		rp-address $ANY_ADDR
		EOF

		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: holds $ANY_ADDR on lo0, the RP ED2's shared tree ends at
		rp-address $ANY_ADDR
		EOF
		return
	fi

	if [ "$SCENARIO" = anycast ]; then
		# No BSR: the RP is configured, the same on all three, because
		# every router has to agree on one RP address and the point is
		# that two routers hold it.  The anycast-rp lines are not here
		# on purpose, check_anycast() adds them once the control half
		# has run without.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router and DR for $SRC_ADDR, registering to
		# $ANY_ADDR, which its route takes to R2
		rp-address $ANY_ADDR
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: holds $ANY_ADDR on lo0, the RP R1's Registers reach,
		# with room for few Registers' state, see check_anycast()
		rp-address $ANY_ADDR
		register-sg-limit $ANY_SG_LIMIT
		EOF

		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: holds $ANY_ADDR on lo0, the RP ED2's shared tree ends at
		rp-address $ANY_ADDR
		EOF
		return
	fi

	if [ "$SCENARIO" = register-filter ]; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router and DR for $SRC_ADDR, so the only
		# router here that ever sends a Register
		EOF

		# The candidacies are the ones every rpt scenario uses and
		# the last line is the whole difference: $REGF_DENY is a
		# prefix R1 has an address out of and does not register
		# from, see REGF_DENY above.
		#
		# The SPT interval is cut from the 100s default for the
		# reason rp-lasthop cuts it, and here it decides an
		# assertion rather than a measurement.  Once the RP accepts
		# the Register it answers from the MRTF_WC arm of
		# receive_pim_register() (src/pim_proto.c), which sends a
		# Register-Stop only for an empty oif list -- and the list
		# is not empty, the DR having joined the shared tree as it
		# registered.  What does send one is the MRTF_SPT arm, so
		# the Register-Stop waits on the switch to the shortest path
		# tree, taken only from age_routes() gated on
		# pim_spt_threshold_timer.  At the default it lands inside
		# or after the second stream depending on timer phase:
		# observed both ways, one run answering in a second and the
		# next taking 41.
		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: bootstrap router and rendezvous point, refusing every
		# Register that reaches it
		bsr-candidate ${EPU}112b priority 1 interval 10
		rp-candidate ${EPU}112b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		spt-threshold packets 0 interval 10
		register-accept-from $REGF_DENY
		EOF

		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: in the domain with nothing to do.  Nobody joins the
		# group here, which is what leaves the RP's table holding
		# the Register's work and nobody else's, see
		# check_register_filter()
		EOF
		return
	fi

	if [ "$SCENARIO" = rp-offpath ]; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, no BSR/RP role
		EOF

		# The candidacies are pinned to epair123a, R2's interface
		# facing the last hop router, so the BSR and the RP are an
		# address on a subnet R3 is directly connected to.  That is
		# what the topology of issue #211 has -- every router there
		# is adjacent to the RP router -- and it is the whole point
		# of the scenario: k_req_incoming() (src/routesock.c) is the
		# only RPF lookup pimd has on BSD, and it used to ask the
		# kernel even for a destination on a subnet of its own.  A
		# route to a connected subnet carries no gateway, so the
		# answer came back with no RPF neighbour, and
		# receive_pim_bootstrap() (src/pim_proto.c) drops a Bootstrap
		# whose RPF neighbour is 0.0.0.0.  The router next to the BSR
		# was then the one router in the domain that never learned
		# the RP set.
		#
		# The interface name is spelled in lower case here, unlike
		# r2.conf everywhere else, so the case-insensitivity fix of
		# PR #252 does not decide the RP address: both this pimd and
		# a pre-#252 one elect $OFFPATH_RP_ADDR, and the scenario
		# then tells them apart on the bootstrap path alone.
		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: bootstrap router and rendezvous point, one hop off the
		# path the traffic takes once the SPT is up
		bsr-candidate ${EP}123a priority 1 interval 10
		rp-candidate ${EP}123a priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		# The shortest path tree is the whole difference between this
		# scenario and rpt: R3's RPF interface towards the source is
		# the direct link to R1, not the one its (*,G) came in on, so
		# the switch has to move the incoming interface.  Its
		# interval is cut from the 100s default for the same reason
		# rp-lasthop cuts it: the decision is only ever taken from
		# age_routes(), and at the default it lands inside or after
		# the measured stream depending on timer phase.
		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: last hop router for the receiver LAN, directly
		# connected to the BSR and the RP
		spt-threshold packets 0 interval 10
		EOF
		return
	fi

	if [ "$SCENARIO" = rp-lasthop ]; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, no BSR/RP role
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: plain transit router between the source and the RP
		EOF

		# The candidacies are pinned to epair203a so the RP address is
		# $RPLH_ADDR, R3's own receiver LAN interface: R3 is then the RP
		# for a group it also has a directly connected member for, and
		# set_incoming() gives its (*,G) the register vif as incoming
		# interface (PIM_IIF_RP in src/route.c).  That is the state
		# router A shows in issue #243.
		#
		# The issue's own configs use a static "rp-address" instead.
		# Not reused here: my_cand_rp_address is only assigned when
		# parsing cand_rp (src/config.c), so with a static RP the
		# register vif check in process_cache_miss() (src/route.c) would
		# make R3 encapsulate its own receiver's mping replies to
		# itself, which is extra traffic in the trace and not what this
		# scenario is about.
		# spt-threshold is left in its default mode (switch on the
		# first packet) but its interval is cut from the default 100s
		# down to 10s, and that is not cosmetic.  On the RP the decision
		# to stop decapsulating and pull the source onto a native path
		# is only ever taken from check_spt_threshold(), and the only
		# caller that runs while traffic flows is age_routes(), gated on
		# pim_spt_threshold_timer (rate_flag in src/route.c).  The
		# cache-miss path cannot do it: the first packet installs a
		# kernel MFC entry, so the kernel never upcalls again.  With the
		# 100s default and a 40s stream the timer fires inside the
		# measurement window or it does not, and this scenario passes or
		# fails on that phase alone - observed both ways on the same
		# lab, 3 registers in one run and 41 in the next.  At 10s it has
		# to fire, so a failure here is pimd, not timer luck.
		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: bootstrap router, rendezvous point *and* last hop router
		bsr-candidate ${EP}203a priority 1 interval 10
		rp-candidate ${EP}203a priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		spt-threshold packets 0 interval 10
		EOF
		return
	fi

	if [ "$SCENARIO" = gif-tunnel-staticrp ]; then
		# The same tunnel as gif-tunnel, but the RP is configured
		# statically on both ends instead of being elected, which is
		# how every pimd.conf quoted in #243 is written.
		#
		# That is not just a different route to the same state.
		# my_cand_rp_address is only ever assigned while parsing
		# cand_rp (src/config.c), never by parse_rp_address(), so on
		# a static RP it stays 0.0.0.0 and every "am I the RP?" test
		# written against it is false on the very router that is the
		# RP.  Two of those matter here:
		#
		#   process_cache_miss() (src/route.c) adds the register vif
		#   to the oif list of a directly connected source unless
		#   group->rpaddr == my_cand_rp_address, so R3 encapsulates
		#   its own receiver's traffic towards itself.
		#
		#   join_or_prune() (src/pim_proto.c) returns PIM_ACTION_PRUNE
		#   instead of PIM_ACTION_NOTHING for an (S,G) with an empty
		#   oif list at the RP, i.e. the RP prunes the source it just
		#   joined.
		#
		# spt-threshold keeps the 10s interval of the other gif
		# scenario so the result does not depend on timer phase.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, tunnel endpoint
		phyint ${EP}101b enable
		phyint $GIF_IF enable
		phyint ${EP}112a disable
		rp-address $RPLH_ADDR 224.0.0.0/16
		EOF

		: > "$WORKDIR/r2.conf"

		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: tunnel endpoint, static RP, and last hop router
		phyint ${EP}203a enable
		phyint $GIF_IF enable
		phyint ${EP}123b disable
		rp-address $RPLH_ADDR 224.0.0.0/16
		spt-threshold packets 0 interval 10
		EOF
		return
	fi

	if [ "$SCENARIO" = gif-tunnel ]; then
		# PIM runs on the LAN and on the tunnel only.  The underlay
		# interface is explicitly disabled rather than just left
		# without a neighbour: that is how the pfSense and Raspberry
		# Pi configs in the issue are written, and it keeps the RPF
		# answer for the remote LAN unambiguously $GIF_IF.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, tunnel endpoint
		phyint ${EP}101b enable
		phyint $GIF_IF enable
		phyint ${EP}112a disable
		EOF

		: > "$WORKDIR/r2.conf"

		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: tunnel endpoint, RP, and last hop router for $RCV_ADDR
		phyint ${EP}203a enable
		phyint $GIF_IF enable
		phyint ${EP}123b disable
		bsr-candidate ${EP}203a priority 1 interval 10
		rp-candidate ${EP}203a priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		spt-threshold packets 0 interval 10
		EOF
		return
	fi

	if is_shared_lan; then
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, no BSR/RP role
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: bootstrap router and rendezvous point, one hop upstream
		# of the shared segment.  Epair112b is spelled with an
		# uppercase letter on purpose, see renames()
		bsr-candidate ${EPU}112b priority 1 interval 10
		rp-candidate ${EPU}112b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		# Every router on the shared segment is pinned to the shared
		# tree for the whole run.  Left at the pimd default they switch
		# to the shortest path tree somewhere inside the measured
		# stream, each on its own timer phase, and the assert election
		# is then between two entries whose RPT bits differ: the RPT
		# bit is the most significant bit of the assert preference, so
		# the winner is decided by which router switched first rather
		# than by the address.  Held on the shared tree both advertise
		# the same preference and metric and compare_metrics()
		# (src/pim_proto.c) falls through to the address, which does
		# not change between runs.
		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: upstream router for R5 on the shared LAN ($SL_R3_ADDR),
		# neither its DR nor its querier
		spt-threshold infinity
		EOF

		cat <<-EOF > "$WORKDIR/r4.conf"
		# R4: PIM DR on the shared LAN ($SL_DR_ADDR, highest address),
		# so ED3's IGMP report is its leaf and nobody else's
		spt-threshold infinity
		EOF

		# R5 is the only router here that may switch to the shortest
		# path tree at all: try_switch_to_spt() (src/route.c) runs only
		# for MRT_IS_LASTHOP or MRT_IS_RP, and R5 is the one with a
		# leaf.  Whether it does is the whole difference between the
		# two scenarios.
		#
		# shared-lan holds it on the shared tree, so both contenders
		# are RPT forwarders and the assert is symmetric.
		#
		# shared-lan-spt lets it switch, and its interval is cut from
		# the 100s default to 10s because the decision is only ever
		# taken from age_routes() gated on pim_spt_threshold_timer: at
		# the default the switch lands inside the measured stream or
		# after it depending on timer phase.  When it fires,
		# switch_shortest_path() (src/route.c) fires the Join/Prune
		# timer and R5 sends an (S,G) Join to its RPF neighbour towards
		# $SRC_ADDR, which is R3.  R3 then has genuine (S,G) forwarding
		# state and R4, which only ever had ED3's (*,G) leaf, does not.
		if [ "$SCENARIO" = shared-lan-spt ]; then
			cat <<-EOF > "$WORKDIR/r5.conf"
			# R5: last hop router for ED2, and the only router here
			# allowed to pull the group onto the shortest path tree
			spt-threshold packets 0 interval 10
			EOF
			return
		fi

		cat <<-EOF > "$WORKDIR/r5.conf"
		# R5: last hop router for ED2, IGMP querier on the shared LAN
		# ($SL_QUERIER_ADDR, lowest address), and the downstream router
		# whose Join gives R3 an oif there
		spt-threshold infinity
		EOF
		return
	fi

	if [ "$SCENARIO" = solo ]; then
		# Every role on one router: the DR for the source, the BSR,
		# the RP the shared tree ends at, and the last hop router for
		# the receiver.  Both candidacies name the interface rather
		# than letting pimd fall back to the highest active address,
		# so $SOLO_RP_ADDR is the RP whichever LAN comes up first.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: BSR, RP, DR and last hop router at once
		bsr-candidate ${EP}101b priority 1 interval 10
		rp-candidate ${EP}101b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF
		return
	fi

	if [ "$SCENARIO" = rpt ]; then
		# Both elections are contested here, and they are decided in
		# opposite directions: RFC 5059 sec. 3.1 gives the BSR to the
		# *higher* priority and RFC 7761 sec. 4.7.1 gives the RP to the
		# *lower* one, so R1 wins the first, R2 the second, and the
		# domain ends up with a bootstrap router that is not its RP --
		# the one shape where a Cand-RP-Adv has to travel to a BSR
		# somewhere else and come back in that BSR's Bootstrap.
		cat <<-EOF > "$WORKDIR/r1.conf"
		# R1: first hop router for $SRC_ADDR, the bootstrap router,
		# and the candidate RP that has to lose
		bsr-candidate ${EP}112a priority $BSR_PRIO interval 10
		rp-candidate ${EP}112a priority $CRP_LOSER_PRIO interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		cat <<-EOF > "$WORKDIR/r2.conf"
		# R2: the candidate RP that has to win, and a candidate BSR
		# that has to lose.  Epair112b is spelled with an uppercase
		# letter on purpose, see renames()
		bsr-candidate ${EPU}112b priority 1 interval 10
		rp-candidate ${EPU}112b priority 20 interval 10
		group-prefix 224.0.0.0 masklen 4
		EOF

		cat <<-EOF > "$WORKDIR/r3.conf"
		# R3: last hop router for the receiver LAN
		EOF
		return
	fi

	cat <<-EOF > "$WORKDIR/r1.conf"
	# R1: first hop router for $SRC_ADDR, no BSR/RP role
	EOF

	cat <<-EOF > "$WORKDIR/r2.conf"
	# R2: bootstrap router and rendezvous point for all of 224.0.0.0/4
	# Epair112b is spelled with an uppercase letter on purpose, see renames()
	bsr-candidate ${EPU}112b priority 1 interval 10
	rp-candidate ${EPU}112b priority 20 interval 10
	group-prefix 224.0.0.0 masklen 4
	EOF

	cat <<-EOF > "$WORKDIR/r3.conf"
	# R3: last hop router for the receiver LAN
	EOF
}

# A sender that never joins anything: sends $KEEP_NUM UDP streams to
# consecutive groups starting at $KEEP_GROUP, five packets per second
# each, until it is killed.
build_msend() {
	cat <<-'EOF' > "$WORKDIR/msend.c"
	#include <arpa/inet.h>
	#include <netinet/in.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <sys/socket.h>
	#include <time.h>

	int main(int argc, char *argv[])
	{
		struct sockaddr_in sin;
		struct in_addr ifa;
		unsigned char ttl = 5;
		char buf[64] = "msend";
		uint32_t base;
		int sd, i, num;

		if (argc != 4) {
			fprintf(stderr, "usage: %s <src-ip> <first-group> <num>\n", argv[0]);
			return 1;
		}

		if (inet_pton(AF_INET, argv[1], &ifa) != 1)
			return 1;
		if (inet_pton(AF_INET, argv[2], &sin.sin_addr) != 1)
			return 1;
		base = ntohl(sin.sin_addr.s_addr);
		num = atoi(argv[3]);

		sd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sd < 0)
			return 1;
		if (setsockopt(sd, IPPROTO_IP, IP_MULTICAST_IF, &ifa, sizeof(ifa)))
			return 1;
		setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(4321);

		while (1) {
			struct timespec ts = { 0, 200000000L };

			for (i = 0; i < num; i++) {
				sin.sin_addr.s_addr = htonl(base + i);
				sendto(sd, buf, sizeof(buf), 0,
				       (struct sockaddr *)&sin, sizeof(sin));
			}
			nanosleep(&ts, NULL);
		}

		return 0;
	}
	EOF

	cc -O2 -o "$MSEND" "$WORKDIR/msend.c" || die "failed building $WORKDIR/msend.c"
}

# Start pimd on one router.  Split out of start() so that a scenario can
# restart a single daemon in the middle of a run: the command line has to
# be the same one, or the router that comes back is not the one the rest of
# the scenario was written against.  box_daemon() appends to the log, so
# what the first incarnation logged is still there afterwards.
start_pimd() {
	r=$1

	# shellcheck disable=SC2086
	box_daemon "$r" "$WORKDIR/$r.daemon.pid" "$WORKDIR/$r.log" \
		"$PIMD" -i "$r" -n $DEBUG $PIMD_ARGS \
		-f "$WORKDIR/$r.conf" \
		-p "$WORKDIR/$r.pid" \
		-u "$WORKDIR/$r.sock"
}

pimd_is_up()   { pimctl "$1" show status >/dev/null 2>&1; }
pimd_is_down() { ! pimd_is_up "$1"; }

# Which of routesock.c and netlink.c the pimd under test was built with.
# Nothing about a running lab betrays it -- both backends answer the same
# RPF lookups, and a netlink build that quietly fell back to the routing
# socket tree would produce an identical, green, meaningless run.  So ask
# the daemon before asserting anything, and stop here if the answer is not
# the one NETLINK asked for.  One router settles it, they all run the same
# binary.
verify_rpf_backend() {
	r=$1

	# Whatever is wrong here is wrong with the tree, not with the lab, so
	# take the jails back down on the way out rather than leave a half
	# started lab for the next run to trip over.
	die_stopped() { stop; die "$@"; }

	wait_for 20 pimd_is_up "$r" || \
		die_stopped "pimd on $r did not come up, see $WORKDIR/$r.log"

	got=$(pimctl "$r" show status | sed -n 's/^RPF Backend *: *//p')
	if [ -z "$got" ]; then
		die_stopped "pimd has no \"RPF Backend\" in show status, it predates the netlink knob"
	fi
	[ "$got" = "$RPF_BACKEND" ] || \
		die_stopped "pimd was built for the \"$got\" RPF backend, not \"$RPF_BACKEND\"" \
		    "(configure --enable-netlink for netlink, without it for the routing socket)"
}

# Stop and start pimd on one router, leaving the lab around it alone.  The
# point of it for assert-recover is the generation ID: RFC 7761 sec. 4.3.1
# has a router pick a new one every time it starts, and that is what tells
# the neighbours this is not the incarnation they were talking to.  A
# SIGHUP would not do -- restart() (src/main.c) keeps the GenID, and the
# neighbours would go on applying what they held for the old one.
#
# SIGKILL, and that is the whole of why this function exists.  On SIGTERM
# cleanup() (src/main.c) sends a Hello with a zero holdtime on every vif,
# which is a router saying goodbye: the neighbours delete it outright and
# reach "NLT Expires" in the Loser state, never "Current Winner's GenID
# Changes".  A router that is cut off says nothing, stays a neighbour for
# the rest of its holdtime, and is still one when its new Hello arrives --
# which is the only way the GenID event happens at all, and is also what a
# router that really rebooted looks like.
restart_pimd() {
	r=$1

	[ -f "$WORKDIR/$r.pid" ] && \
		${SUDO} pkill -9 -F "$WORKDIR/$r.pid" 2>/dev/null || true
	wait_for 15 pimd_is_down "$r" || true
	start_pimd "$r"
}

start() {
	check_req

	if box_exists r1; then
		die "lab already running, run '$0 stop' first"
	fi

	# Owned by the invoking user: pimd runs as root and can still drop its
	# PID file and control socket in here, but mping is built unprivileged.
	mkdir -p "$WORKDIR"
	[ "$SANITIZE" = no ] || mkdir -p "$SAN_DIR"

	print "Building mping (multicast ping) from the pimd tree ..."
	cc -O2 -o "$MPING" "$PIMD_SRC/test/mping.c" || \
		die "failed building $PIMD_SRC/test/mping.c"

	print "Building igmpv3 (membership report generator) ..."
	cc -O2 -o "$IGMPV3" "$PIMD_SRC/test/igmpv3.c" || \
		die "failed building $PIMD_SRC/test/igmpv3.c"

	print "Building pimsend (crafted PIM message generator) ..."
	cc -O2 -o "$PIMSEND" "$PIMD_SRC/test/pimsend.c" || \
		die "failed building $PIMD_SRC/test/pimsend.c"

	print "Disabling multicast loopback on the host (restored by the last stop) ..."
	disable_mcast_loop

	print "Creating vnet jails and links ..."
	write_configs
	create_lans
	for box in $BOXES; do
		create_box "$box"
	done

	print "Starting pimd on $(pim_routers | tr ' ' ',') ($RPF_BACKEND RPF) ..."
	for r in $(pim_routers); do
		start_pimd "$r"
	done
	verify_rpf_backend "$(pim_routers | awk '{ print $1 }')"

	if [ "$SCENARIO" = keepalive ]; then
		print "Starting the source on ED1, $KEEP_NUM groups from $KEEP_GROUP ..."
		build_msend
		box_daemon ed1 "$WORKDIR/msend.pid" "$WORKDIR/msend.log" \
			"$MSEND" "$SRC_ADDR" "$KEEP_GROUP" "$KEEP_NUM"
	fi

	print "Lab is up ($SCENARIO).  Poke at it with:"
	echo "  $(box_hint r2) $PIMCTL -u $WORKDIR/r2.sock show pim detail"
	echo "  $(box_hint r3) $MFC_SHOW_CMD"
	echo "  $(box_hint ed2) $MPING -r -i $ED2_IF $GROUP"
	echo "  tail -f $WORKDIR/r1.log"
}

# --- assertions -------------------------------------------------------

has_neighbor() { pimctl "$1" show neighbor 2>/dev/null | grep -q "$2"; }

# Does router $1 hold $3 as a secondary address of its neighbour $2?  The
# detail listing puts each one on a line of its own under the neighbour's.
has_secaddr() {
	pimctl "$1" show neighbor detail 2>/dev/null | awk -v n="$2" -v a="$3" '
		$NF != "secondary" { cur = $2; next }
		cur == n && $1 == a { found = 1 }
		END { exit !found }
	'
}
has_iface()    { pimctl "$1" show interface 2>/dev/null | grep -q "^$2 "; }

# config_vifs_from_kernel() logs a point-to-point vif as "(local -> peer)"
# and an ordinary one as "(local on subnet X)", and only the first branch
# sets VIFF_POINT_TO_POINT | VIFF_REXMIT_PRUNES and takes uv_rmt_addr from
# ifa_dstaddr (src/config.c).  Asserting on the wording is crude but it is
# the only externally visible difference, and without it the gif scenario
# would still pass if the tunnel ever came up as a plain subnet vif, i.e.
# while testing nothing it claims to test.
took_p2p_branch() {
	${SUDO} grep -q "Installing $GIF_IF ($2 -> $3)" "$WORKDIR/$1.log" 2>/dev/null
}
has_rp()       { pimctl "$1" show rp 2>/dev/null | grep -q "$2"; }

# The BSR router $1 has elected, out of the "Elected BSR" block of
# "show status"; empty while it has none
elected_bsr() {
	pimctl "$1" show status 2>/dev/null | awk '
		/^Elected BSR/      { want = 1; next }
		want && $1 == "Address" { print $3; exit }
	'
}
elected_bsr_is() { [ "$(elected_bsr "$1")" = "$2" ]; }

# Does router $1 hold $2 in the candidate RP set it was given, "show crp",
# which is the set the BSR distributes rather than the one RP it elects
has_crp() {
	pimctl "$1" show crp 2>/dev/null | \
		awk -v a="$2" '$2 == a { found = 1 } END { exit !found }'
}

# ... and both of them, for wait_for(): a candidate reaches a router in the
# BSR's next Bootstrap, and the two candidacies here are not advertised in
# the same one, so the set is complete an advertisement interval after it
# first has anything in it at all
has_both_crps() { has_crp "$1" "$2" && has_crp "$1" "$3"; }
has_mrt()      { pimctl "$1" show mrt 2>/dev/null | grep -q "$2"; }

# Every (S,G) the source is sending to, one per line, as pimctl shows them
sources() { pimctl r1 show mrt 2>/dev/null | awk -v s="$SRC_ADDR" '$1 == s { print $2 }'; }
all_sources_up() { [ "$(sources | wc -l)" -eq "$KEEP_NUM" ]; }

# "<group> <entry timer>" per (S,G), read out of the detailed dump.  The
# entry timer is the only reliable witness: an entry that is recreated by
# the next cache miss 1.5s later looks exactly like one that was never
# deleted if all you count is table rows, but a recreated entry always
# comes back with its timer at 0.
source_timers() {
	pimctl r1 show mrt detail 2>/dev/null | awk -v s="$SRC_ADDR" '
		$1 == s   { grp = $2; next }
		grp == "" { next }
		/TIMERS/  { want = 1; next }
		want      { print grp, $1; grp = ""; want = 0 }
	'
}

# Vif index of the incoming interface of ($2,$3) on router $1, or nothing
# when there is no such entry.  "pimctl show mrt detail" prints the iif as
# a per-vif map, one character per vif with 'I' on the incoming one
# ("Incoming     : .I.."), so the offset of the 'I' is the vif number.
# Vif 0 is always the register vif, PIMREG_VIF in src/vif.h reserves it.
route_iif() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" '
		$1 == s && $2 == g { want = 1; next }
		want && $1 == "Incoming" { print index($3, "I") - 1; want = 0 }
	'
}

# PIM registers R3 has decapsulated so far.  One per data packet means the
# RP never got off the register vif; a handful means it register-stopped
# the first hop router early, as it should.
registers_seen() {
	${SUDO} grep -c "Received PIM register:" "$WORKDIR/r3.log" 2>/dev/null || true
}

# The "Outgoing oifs" map of ($2,$3) on router $1, same one-character-per-vif
# encoding as route_iif(), so position 0 is the register vif.
route_oifs() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" '
		$1 == s && $2 == g { want = 1; next }
		want && $1 == "Outgoing" { print $3; want = 0 }
	'
}

has_static_rp() { pimctl "$1" show rp 2>/dev/null | grep "$2" | grep -q Static; }

# Any of the per-vif maps of ($2,$3) on router $1, named by the first word
# of its line in "show mrt detail": Joined, Pruned, Leaves, Asserted or
# Outgoing.  Same one-character-per-vif encoding as route_oifs().
route_map() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" -v k="$4" '
		$1 == s && $2 == g { want = 1; next }
		want && $1 == k    { print $3; want = 0 }
	'
}

# Vif index of interface $2 on router $1.  "show interface" prints one row
# per vif in vif order and skips the register vif, which src/vif.h reserves
# as vif 0 (PIMREG_VIF), so the Nth row is vif N.  -t drops both table
# headings, leaving nothing but the rows.
vif_index() {
	pimctl "$1" -t show interface 2>/dev/null | \
		awk -v ifn="$2" 'NF { n++; if ($1 == ifn) { print n; exit } }'
}

# Is the slot interface $2 owns set in the map $3 read out of router $1?
map_isset() {
	idx=$(vif_index "$1" "$2")
	[ -n "$idx" ] || return 1
	[ -n "$3" ] || return 1

	[ "$(printf '%s' "$3" | cut -c "$((idx + 1))")" != "." ]
}

# Does router $1 forward this scenario's stream onto interface $2, and has
# it been asserted off it?
#
# Forwarding is read out of the kernel rather than out of pimd, because
# neither pimd entry answers it on its own: a router that lost the assert
# can still show the LAN in the oifs of its (*,G), which is state about the
# group and not about this source, and a router that won can be forwarding
# off a kernel cache hung on its (*,G) with no (S,G) of its own to read.
# The MFC is the forwarding decision itself, and its vif numbers are the
# ones pimd handed the kernel, so vif_index() maps names onto them.
#
# Asserted state is read off both entries, since which one the assert
# landed on depends on what the router held when it arrived.
forwards_on() {
	idx=$(vif_index "$1" "$2")
	[ -n "$idx" ] || return 1

	mfc_forwards_on "$1" "$SRC_ADDR" "$3" "$idx"
}

asserted_on() {
	for src in ANY "$SRC_ADDR"; do
		if map_isset "$1" "$2" "$(route_map "$1" "$src" "$3" Asserted)"; then
			return 0
		fi
	done

	return 1
}

# The per-vif Assert state map of ($2,$3) on router $1: 'W' on an interface
# this router won the election on, 'L' on one it lost, '.' where it holds
# no assert state.  Same encoding as route_map(), but not readable through
# it: "Assert state : <map>" puts the map in field 4, where every other
# per-vif line of "show mrt detail" has it in field 3.
route_assert_map() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" '
		$1 == s && $2 == g                      { want = 1; next }
		want && $1 == "Assert" && $2 == "state" { print $4; want = 0 }
	'
}

# The Assert state character interface $2 holds for group $3 on router $1,
# read off whichever entry carries it the way asserted_on() does.  Prints
# 'W' or 'L' and succeeds; prints nothing and fails where the router holds
# neither, which is both "NoInfo" and "no such entry" -- a caller that
# needs those apart has to ask about the entry separately.
assert_state_on() {
	idx=$(vif_index "$1" "$2")
	[ -n "$idx" ] || return 1

	for src in "$SRC_ADDR" ANY; do
		map=$(route_assert_map "$1" "$src" "$3")
		[ -n "$map" ] || continue

		case $(printf '%s' "$map" | cut -c "$((idx + 1))") in
		W) echo W; return 0 ;;
		L) echo L; return 0 ;;
		esac
	done

	return 1
}

# Has router $1 joined group $3 towards interface $2?  Re-read on every
# call, so it can be polled with wait_for().
joined_on() {
	map_isset "$1" "$2" "$(route_map "$1" ANY "$3" Joined)"
}

# The DR address pimd shows for interface $2 on router $1.  A router that is
# the DR itself prints its own address here (show_interface() in src/ipc.c).
iface_dr() {
	pimctl "$1" -t show interface 2>/dev/null | \
		awk -v ifn="$2" '$1 == ifn { print $7; exit }'
}

# The IGMP querier pimd shows for interface $2 on router $1, "Local" when
# this router won the election.  "show igmp" prints an interface table and a
# group table, both keyed on the interface name and both stripped of their
# headings by -t, so the rows are told apart by the interface state in the
# second column.
iface_querier_is() { [ "$(iface_querier "$1" "$2")" = "$3" ]; }

iface_querier() {
	pimctl "$1" -t show igmp 2>/dev/null | \
		awk -v ifn="$2" '$1 == ifn && $2 ~ /^(Up|Down|Disabled)$/ { print $3; exit }'
}

# Have all three routers on the shared LAN settled on r5 as the querier?
# Polled rather than read once, because this election converges on a timer
# rather than on anything a router sends in reply: a pimd believes it is the
# querier until it hears a query from a lower address, and queries go out
# every igmp_query_interval / 4 while the startup count lasts
# (query_groups(), src/igmp_proto.c, three of them from
# IGMP_STARTUP_QUERY_COUNT) and every igmp_query_interval, 125s, after that.
# A router that came up just behind r5 therefore reads "Local" for up to
# half a minute, and a busy host is enough to land a single reading in that
# window -- a lab still converging, not an election that went the wrong way.
# Seen for real: `run all` failed here twice on a host compiling LLVM
# alongside it, with the same pimd that passed the scenario on its own.
queriers_settled() {
	[ "$(iface_querier r5 ${EP}503b)" = "Local" ] || return 1
	[ "$(iface_querier r3 "$SL_R3_IF")" = "$SL_QUERIER_ADDR" ] || return 1
	[ "$(iface_querier r4 "$SL_R4_IF")" = "$SL_QUERIER_ADDR" ] || return 1

	return 0
}

# Run the ED1 -> ED2 stream and watch the RP while it is in flight.
# Sets: replies, regs, sg_seen, sg_native, selfreg.
#
# The sampling has to happen during the stream.  Killing the receiver
# expires ED2's membership within seconds, the (*,G) loses its leaf and
# the (S,G) is rebuilt or aged out, so a dump taken afterwards describes a
# different router than the one under test.
#
# Vif 0 is the register vif, PIMREG_VIF in src/vif.h reserves it.  An
# (S,G) still incoming on vif 0 means the RP is living off the
# encapsulated copies alone and never joined the shortest path tree
# towards the source, which is the state router A shows in #243.
run_stream_and_sample() {
	regs_before=$(registers_seen)
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$STREAM_PKTS" -w 90 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 &
	sender=$!

	sg_seen=
	sg_native=
	selfreg=
	deadline=$(($(date +%s) + STREAM_PKTS + 30))
	while [ "$(date +%s)" -lt "$deadline" ]; do
		# Does the RP encapsulate its own directly connected source
		# towards itself?  Sampled every round, because it shows up
		# as soon as ED2 answers, well before the loop breaks below.
		case $(route_oifs r3 "$RCV_ADDR" "$GROUP") in
		o*) selfreg=yes ;;
		esac

		sg_iif=$(route_iif r3 "$SRC_ADDR" "$GROUP")
		if [ -n "$sg_iif" ]; then
			sg_seen=$sg_iif
			if [ "$sg_iif" -ne 0 ]; then
				sg_native=$sg_iif
				break
			fi
		fi
		sleep 1
	done

	wait "$sender" 2>/dev/null || true
	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true
	regs=$(( $(registers_seen) - regs_before ))

	# Counted from the replies, not from the receiver's own log: mping
	# writes that log through a block buffered stdout and it is killed,
	# not stopped, so the buffer never reaches the disk.  A reply only
	# exists because a packet arrived at ED2, so the count is still a
	# lower bound on what the #243 direction delivered.
	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
}

# shared-lan: run the ED1 -> ED2 stream, then read the receiver LAN state
# off both last hop routers.  Sets: replies, fwd3, fwd4, ast3, ast4, reg3.
#
# The sampling happens after the sender is done but while the receiver is
# still joined, which is the only window where the answer means anything:
# the first packets of the stream are forwarded by both routers by
# definition, that duplicate is what triggers the assert, so sampling early
# reports a race rather than a result; and killing the receiver expires
# ED2's membership within seconds, after which both routers drop the leaf
# and the assert state goes with it.
run_stream_and_sample_shared() {
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$STREAM_PKTS" -w 90 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 || true

	fwd3=
	fwd4=
	ast3=
	ast4=
	reg3=
	if forwards_on r3 "$SL_R3_IF" "$GROUP"; then fwd3=yes; fi
	if forwards_on r4 "$SL_R4_IF" "$GROUP"; then fwd4=yes; fi
	if asserted_on r3 "$SL_R3_IF" "$GROUP"; then ast3=yes; fi
	if asserted_on r4 "$SL_R4_IF" "$GROUP"; then ast4=yes; fi

	# Did R5's switch actually reach R3, i.e. does R3 hold (S,G) forwarding
	# state of its own?  Without this the assert outcome below could not be
	# read: a run where R5 never switched has two RPT forwarders and says
	# nothing about which tree the election preferred.
	sg3=
	if map_isset r3 "$SL_R3_IF" "$(route_map r3 "$SRC_ADDR" "$GROUP" Joined)"; then
		sg3=yes
	fi

	# Vif 0 is the register vif.  R3 is not the DR for the shared LAN, so
	# process_cache_miss() (src/route.c) must never add it to the oifs of
	# a source sitting there - registering ED3 is R4's job.
	case $(route_oifs r3 "$SL_ED3_ADDR" "$GROUP") in
	o*) reg3=yes ;;
	esac

	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true

	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
}

# Who holds the shared LAN, read off both contenders' kernel forwarding
# caches: the assert loser's oif is gone from the MFC, not merely marked.
sl_lan_is_held_by() {
	case $1 in
	r3)	forwards_on r3 "$SL_R3_IF" "$GROUP" || return 1
		! forwards_on r4 "$SL_R4_IF" "$GROUP" ;;
	r4)	forwards_on r4 "$SL_R4_IF" "$GROUP" || return 1
		! forwards_on r3 "$SL_R3_IF" "$GROUP" ;;
	esac
}

sl_set_rp_metric() {
	box_route_change "$1" "$SL_RP_NET" "$SL_RP_GW" "$2" >/dev/null
}

# The assert election decided by the routing table instead of by the
# addresses.  R3 and R4 are equally far from the RP, so step 9 above ties
# on the metric and the address settles it: R4 wins.  Give the loser of the
# moment the better route to the RP and RFC 7761 sec. 4.6.3 says the LAN has
# to change hands, both contenders forwarding off the shared tree and
# rpt_assert_metric(G,I) being MRIB.metric(RP(G)).
#
# Each half moves the metric of the router that lost, which is what makes
# them quick: sec. 4.6.1 leaves the Loser state on "my metric becomes better
# than the assert winner's metric", evaluated once per pass, while a winner
# whose own metric got worse says nothing about it until its Assert Timer
# expires, three minutes later.  The first half is also the only assertion
# in this file where an election is decided against the addresses: R3 wins
# it with the lower one.
#
# Both halves rest on the metric being the kernel's.  While it was the
# constant from pimd.conf, `route change -metric` moved nothing at all and
# neither half could ever pass.
#
# The stream has to run underneath both: an election starts at a data
# packet arriving on an interface that is not the entry's iif, so a LAN
# nobody is sending to keeps whatever it decided last.
check_assert_metric() {
	print "12. The assert election follows the unicast route metric"

	if ! route_has_metric; then
		skip "route(8) here has no -metric, so nothing can move the metric pimd asserts with"
		return 0
	fi

	box_run ed3 "$MPING" -r -i ${EP}603b -p "$SL_JOIN_PORT" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/joiner-metric.log" 2>&1 &
	joiner=$!
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver-metric.log" 2>&1 &
	receiver=$!
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$SL_METRIC_PKTS" \
		-w "$SL_METRIC_PKTS" "$GROUP" \
		>"$WORKDIR/sender-metric.log" 2>&1 &
	sender=$!

	if wait_for "$SL_METRIC_WAIT" sl_lan_is_held_by r4; then
		sl_set_rp_metric r3 "$SL_METRIC_NEAR"
		if wait_for "$SL_METRIC_WAIT" sl_lan_is_held_by r3; then
			ok "r3 reached the RP at metric $SL_METRIC_NEAR against r4's $SL_METRIC_FAR and took the LAN, with the lower address"
		else
			fail "r4 keeps the LAN though r3 is $SL_METRIC_NEAR from the RP and it is $SL_METRIC_FAR, the Assert carries something that is not the route's metric"
		fi

		sl_set_rp_metric r3 "$SL_METRIC_FAR"
		sl_set_rp_metric r4 "$SL_METRIC_NEAR"
		if wait_for "$SL_METRIC_WAIT" sl_lan_is_held_by r4; then
			ok "the metrics swapped back and so did the LAN, without waiting Assert_Time out"
		else
			fail "r4 has the better metric and is still the assert loser, the Loser state has no way out but its timer"
		fi
	else
		fail "no assert settled the LAN in ${SL_METRIC_WAIT}s with both metrics equal, the halves below cannot be read"
	fi

	# Back to the baseline both of them start at, so that a lab left
	# running afterwards is the one the header describes
	sl_set_rp_metric r3 "$SL_METRIC_FAR"
	sl_set_rp_metric r4 "$SL_METRIC_FAR"

	kill "$sender" "$joiner" "$receiver" 2>/dev/null || true
	wait "$sender" "$joiner" "$receiver" 2>/dev/null || true
}

# How many times r3 has been let out of the Loser state by the winner
# coming back under a new generation ID.  Counted rather than matched,
# because r3's log is one file across the restart and an earlier flap
# would answer a plain grep.
#
# "restarted" and not the other half of Actions A5: assert_forget_winner()
# (src/pim_proto.c) is reached by both "Current Winner's GenID Changes"
# and "NLT Expires" and says which, and only the first of those is what
# this step sets up.  Matching either would pass on a pimd that has no
# GenID handling at all, since a neighbour deleted for any reason lands in
# the same function.
ar_resumes() {
	n=$(${SUDO} grep -c "restarted, resuming" "$WORKDIR/r3.log" 2>/dev/null || true)
	echo "${n:-0}"
}

ar_resumed_since() { [ "$(ar_resumes)" -gt "$1" ]; }

ar_restore_addr() {
	box_addr_del r4 "$SL_R4_IF" "$AR_DR_NEW" 2>/dev/null || true
	box_addr_add r4 "$SL_R4_IF" "$SL_DR_ADDR/24" 2>/dev/null || true
}

# The Assert state router $1 holds for (*,$3) on interface $2, which for a
# downstream router is its RPF interface: L there is Loser state, whose
# winner is RPF'(*,G).  Read off the (*,G) entry alone, the one whose
# upstream the Joins of the whole group follow.
ar_iif_assert_state() {
	idx=$(vif_index "$1" "$2")
	[ -n "$idx" ] || return 1

	map=$(route_assert_map "$1" ANY "$3")
	[ -n "$map" ] || return 1
	printf '%s' "$map" | cut -c "$((idx + 1))"
}

ar_cleanup() {
	kill "$sender" "$joiner" "$receiver" 2>/dev/null || true
	wait "$sender" "$joiner" "$receiver" 2>/dev/null || true
}

ar_dump() {
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in r3 r4; do
		dprint "--- $r: pimctl show interface ---"
		pimctl "$r" show interface 2>&1 || true
		dprint "--- $r: pimctl show mrt detail ---"
		pimctl "$r" show mrt detail 2>&1 | head -40 || true
		dprint "--- $r: $MFC_SHOW_CMD ---"
		mfc_show "$r" 2>&1 || true
	done
}

# assert-recover: the two ways RFC 7761 sec. 4.6 lets a router out of the
# assert state it is holding, neither of which any other scenario reaches.
#
# Both need what only a shared segment has, two PIM routers contending for
# one link, so this runs on the shared-lan topology and inherits its
# configuration whole: R3 and R4 both put $GROUP on $BR_RECEIVER, R4 wins
# the election on the higher address, R3 is the loser holding the LAN in
# its asserted oifs.  That state is the starting point, not the subject --
# step 9 of shared-lan is where it is asserted for its own sake.
#
# The winner's GenID changes.  R4's pimd is restarted, which is quick
# enough that R3 never times the neighbour out, so the Hello that comes
# back is from a router R3 still knows, carrying a generation ID it does
# not: the Loser state of sec. 4.6.1 and sec. 4.6.2 returns to NoInfo on
# that, Actions A5.  Without it R3 holds an interface off for a router
# that no longer knows it won, for the rest of Assert_Time.  Asserted from
# R3's log rather than from a dump, because the window is not one a poll
# can promise to catch: R4 relearns ED3's membership from its own startup
# IGMP queries within a few seconds and takes the LAN straight back, while
# the log line stays.  A restart slow enough to outlast R3's neighbour
# holdtime instead arrives as "NLT Expires", which is the same Actions A5
# through the other door and the same line in the log.
#
# The winner's address changes.  R4's address on the LAN is replaced
# inside its own subnet -- the DHCP lease of the renumber scenario, but on
# a segment where an election has already been decided.  Both addresses
# are above R3's, so the election has the answer it had before and the
# only thing under test is pimd's memory of having won it.  That memory
# used to be "the winner is whatever address this interface has now",
# which renumbering falsified: R4 read itself back as the loser of its own
# election.  Step 7 is where that shows.  It has to move downwards to show
# at all, and what it costs once it does is less than it appears; both are
# measurements rather than predictions, and both are written down at the
# steps they belong to.
#
# Not covered here: the other half of the same fix, that an assert is
# given back only on the link the departed neighbour was on.  Telling that
# apart needs one router reachable at the same address on two of its own
# links, which no topology in this file builds.
#
# Takes about four minutes, longer if the elections are slow.
check_assert_recover() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. The RP set is distributed by the bootstrap router"
	for r in $ROUTERS; do
		if wait_for 90 has_rp "$r" "$RP_ADDR"; then
			ok "$r learned RP $RP_ADDR"
		else
			fail "$r never learned RP $RP_ADDR (BSR/cand-RP path)"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	# An election starts at a data packet arriving on an interface that is
	# not the entry's iif, so the stream underneath all of this is not
	# scenery: a LAN nobody is sending to keeps whatever it decided last,
	# and every step below would read the previous step's answer.
	box_run ed3 "$MPING" -r -i ${EP}603b -p "$SL_JOIN_PORT" -t 5 -W 900 "$GROUP" \
		>"$WORKDIR/joiner-recover.log" 2>&1 &
	joiner=$!
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 900 "$GROUP" \
		>"$WORKDIR/receiver-recover.log" 2>&1 &
	receiver=$!
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$AR_PKTS" -w "$AR_PKTS" "$GROUP" \
		>"$WORKDIR/sender-recover.log" 2>&1 &
	sender=$!

	print "3. An assert election settles the shared LAN on r4"
	if wait_for "$AR_WAIT" sl_lan_is_held_by r4; then
		ok "r4 ($SL_DR_ADDR) holds $GROUP on the LAN and r3 has been asserted off it"
	else
		fail "no assert settled the LAN in ${AR_WAIT}s, nothing below can be read"
		ar_cleanup
		ar_dump
		return 1
	fi

	print "4. pimctl names the winner and the loser of that election"
	st4=$(assert_state_on r4 "$SL_R4_IF" "$GROUP" || true)
	st3=$(assert_state_on r3 "$SL_R3_IF" "$GROUP" || true)
	if [ "$st4" = W ] && [ "$st3" = L ]; then
		ok "r4 reads W on $SL_R4_IF, r3 reads L on $SL_R3_IF"
	else
		fail "assert state is wrong: r4 '${st4:-none}' (want W), r3 '${st3:-none}' (want L)"
	fi
	# And the router downstream of the election follows it.  R5's RPF
	# neighbour for the RP is R3, and RFC 7761 sec. 4.1.6 makes RPF'(*,G)
	# the Assert winner instead, which sec. 4.6.2 records as Loser state on
	# R5's RPF interface.  pimd measured each Assert there against R5's own
	# route to the RP, found R4's inferior, and went on sending its Joins
	# to R3 -- and every one of them took R3 out of its Loser state again,
	# "Receive Join(*,G)" in the same section, so the LAN flapped once a
	# Join/Prune period and step 5 failed whenever the flap and R4's
	# restart coincided.
	st5=$(ar_iif_assert_state r5 "$SL_R5_IF" "$GROUP" || true)
	if [ "$st5" = L ]; then
		ok "r5 reads L on $SL_R5_IF, its RPF interface, so its Joins go to r4"
	else
		fail "r5 reads '${st5:-none}' on $SL_R5_IF (want L): it ignores the Assert winner on its RPF interface"
	fi
	[ "$FAILED" -eq 0 ] || { ar_cleanup; ar_dump; return 1; }

	print "5. The winner restarts and the loser stops waiting for it"
	# Not in the default debug set, and nothing else reports this one
	pimctl r3 debug asserts >/dev/null 2>&1 || true
	resumes=$(ar_resumes)
	restart_pimd r4
	if wait_for "$AR_WAIT" ar_resumed_since "$resumes"; then
		ok "r3 returned to NoInfo on the new GenID, rather than waiting Assert_Time out"
	else
		fail "r3 is still the assert loser of a router that has restarted; sec. 4.6.1 'Current Winner's GenID Changes' did nothing"
		if [ "$(ar_resumes)" -eq "$resumes" ] && logged r3 "went away, resuming"; then
			dprint "   r3 got there through NLT instead: r4 was not killed hard enough to stay a neighbour"
		fi
	fi
	[ "$FAILED" -eq 0 ] || { ar_cleanup; ar_dump; return 1; }

	print "6. The LAN goes back to r4 once it is up again"
	if wait_for "$AR_WAIT" sl_lan_is_held_by r4; then
		ok "r4 won the election again after its restart"
	else
		fail "the LAN never came back to r4 after its restart, the renumbering below cannot be read"
		ar_cleanup
		ar_dump
		return 1
	fi

	print "7. The winner is renumbered and still knows it won the election"
	box_addr_del r4 "$SL_R4_IF" "$SL_DR_ADDR"
	box_addr_add r4 "$SL_R4_IF" "$AR_DR_NEW/24"
	if wait_for 60 iface_is r4 "$SL_R4_IF" "$AR_DR_NEW"; then
		ok "r4: the VIF on $SL_R4_IF moved to $AR_DR_NEW"
	else
		fail "r4: pimd never picked the new address up, see $WORKDIR/r4.log"
		ar_restore_addr
		ar_cleanup
		ar_dump
		return 1
	fi

	# 'L' here is the bug, and with it reintroduced this is the
	# assertion that reports it: measured, 2 runs out of 2.  Holding
	# nothing is neither answer -- r4 has just bounced the VIF, and an
	# entry it has already rebuilt from scratch has no assert state yet
	# for an honest reason -- so that case is reported and not judged.
	st4=$(assert_state_on r4 "$SL_R4_IF" "$GROUP" || true)
	case $st4 in
	W)	ok "r4 still reads W on $SL_R4_IF, it kept the election it had won" ;;
	L)	fail "r4 reads L on $SL_R4_IF: it is the loser of its own election, the winner was remembered as an address that has since moved" ;;
	*)	dprint "   r4 holds no assert state on $SL_R4_IF yet, it rebuilt the entry before this was read: neither answer" ;;
	esac

	# Not a second reading of step 7, and deliberately not described as
	# one: with the bug reintroduced this still passed, both runs.  The
	# inverted state is real and step 7 sees it, but r4 tears its entry
	# down and builds it again while the VIF is bouncing, and the rebuilt
	# entry asserts from NoInfo like any other -- so the LAN converges on
	# one forwarder either way and the duplicate this was expected to
	# leave behind does not happen.  What it is worth keeping for is the
	# convergence itself, which nothing else here covers: a renumbering
	# on a segment where an election has been decided has to end with one
	# forwarder, and within seconds rather than within Assert_Time.
	print "8. The LAN settles on one forwarder again after the renumbering"
	if wait_for "$AR_WAIT" sl_lan_is_held_by r4; then
		ok "r4 holds $GROUP alone from $AR_DR_NEW, r3 gave it up"
	else
		fail "r3 and r4 both still forward $GROUP ${AR_WAIT}s after the renumbering, nothing settled the LAN again"
	fi

	# Back to the addressing the header describes, for a lab left running
	ar_restore_addr
	ar_cleanup

	echo
	if [ "$FAILED" -eq 0 ]; then
		if [ "$XFAILED" -gt 0 ]; then
			print "RESULT: PASS ($XFAILED known deviation(s), see above)"
		else
			print "RESULT: PASS"
		fi
		return 0
	fi
	ar_dump
	return 1
}

check() {
	box_exists r1 || die "lab is not running, run '$0 start'"

	# "run all" walks the scenarios in one shell, and every check_*()
	# gates its later assertions on "[ $FAILED -eq 0 ] || return 1".
	# Without this the first scenario to fail takes every scenario after
	# it down at its first checkpoint, with all of their assertions
	# printing ok on the way out - a clean looking run that tested
	# nothing.
	FAILED=0
	XFAILED=0

	case $SCENARIO in
	solo)       check_solo; return $? ;;
	keepalive)  check_keepalive; return $? ;;
	rp-lasthop) check_rp_lasthop; return $? ;;
	rp-offpath) check_rp_offpath; return $? ;;
	gif-tunnel) check_gif_tunnel; return $? ;;
	gif-tunnel-staticrp) check_gif_staticrp; return $? ;;
	shared-lan|shared-lan-spt) check_shared_lan; return $? ;;
	assert-recover) check_assert_recover; return $? ;;
	ssm)        check_ssm; return $? ;;
	ssm-range)  check_ssm_range; return $? ;;
	alias)      check_alias; return $? ;;
	ifnew)      check_ifnew; return $? ;;
	ifgone)     check_ifgone; return $? ;;
	renumber)   check_renumber; return $? ;;
	register-filter) check_register_filter; return $? ;;
	crafted)    check_crafted; return $? ;;
	fuzz)       check_fuzz; return $? ;;
	static-rp)  check_static_rp; return $? ;;
	anycast)    check_anycast; return $? ;;
	anycast-dr) check_anycast_dr; return $? ;;
	privsep)    check_privsep; return $? ;;
	esac

	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. PIM neighbors are discovered over the epairs"
	if wait_for 60 has_neighbor r1 10.0.12.2; then
		ok "r1 sees r2 (10.0.12.2)"
	else
		fail "r1 never saw r2, PIM hello is not crossing ${EP}112"
	fi
	if wait_for 60 has_neighbor r2 10.0.23.3; then
		ok "r2 sees r3 (10.0.23.3)"
	else
		fail "r2 never saw r3, PIM hello is not crossing ${EP}123"
	fi
	if wait_for 60 has_neighbor r3 10.0.23.2; then
		ok "r3 sees r2 (10.0.23.2)"
	else
		fail "r3 never saw r2"
	fi

	print "3. The RP set is distributed by the bootstrap router"
	for r in $ROUTERS; do
		if wait_for 90 has_rp "$r" "$RP_ADDR"; then
			ok "$r learned RP $RP_ADDR"
		else
			fail "$r never learned RP $RP_ADDR (BSR/cand-RP path)"
		fi
	done

	# mping echoes every packet back to the group, so a reply proves both
	# the (10.0.1.10,G) tree towards ED2 and the (10.0.3.10,G) tree back.
	# Its own exit code demands *every* packet be answered, which no PIM
	# network can do while it is still converging - the first packets are
	# what builds the tree.  Count the replies instead and require the
	# stream to be flowing rather than perfect.
	# The elections themselves, which every other scenario leaves
	# uncontested: one candidate of each kind, both on R2.  Here R1 is a
	# candidate for both and has to win exactly one of them, so a
	# Cand-RP-Adv reaches a BSR that is not the sender, and the RP set
	# that comes back carries a candidate the BSR did not elect.
	print "4. The bootstrap router is elected, and it is not the RP"
	for r in $ROUTERS; do
		if wait_for 90 elected_bsr_is "$r" "$R1_UP_ADDR"; then
			ok "$r elected $R1_UP_ADDR as BSR, priority $BSR_PRIO beating R2's 1"
		else
			fail "$r has BSR '$(elected_bsr "$r")', expected $R1_UP_ADDR"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	if [ "$R1_UP_ADDR" != "$RP_ADDR" ]; then
		ok "the BSR ($R1_UP_ADDR) and the RP ($RP_ADDR) are different routers"
	else
		fail "the BSR and the RP are the same address, the scenario tests nothing"
	fi
	if wait_for 90 has_both_crps r3 "$R1_UP_ADDR" "$RP_ADDR"; then
		ok "r3 was given both candidate RPs and elected the better one, $RP_ADDR"
	else
		fail "r3's candidate RP set is missing one of $R1_UP_ADDR and $RP_ADDR: $(pimctl r3 -t show crp 2>/dev/null | tr '\n' ' ')"
	fi

	print "5. Multicast is forwarded from ED1 to ED2 through the RP"
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 90 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	sleep 2
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c 40 -w 60 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 || true
	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true

	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
	if [ "$replies" -ge "$MIN_REPLIES" ]; then
		ok "ED1 -> $GROUP -> ED2, $replies replies"
	else
		fail "only $replies replies, want >= $MIN_REPLIES, see $WORKDIR/sender.log"
	fi

	print "6. pimd installed the route it claims to have"
	if has_mrt r3 "$GROUP"; then
		ok "r3 has $GROUP in its multicast routing table"
	else
		fail "r3 has no $GROUP entry in 'pimctl show mrt'"
	fi
	if has_mrt r1 "$SRC_ADDR"; then
		ok "r1 has an (S,G) for source $SRC_ADDR"
	else
		fail "r1 has no (S,G) for $SRC_ADDR"
	fi

	print "7. The kernel MFC in each vnet agrees with pimd"
	if has_mfc r3 "$GROUP"; then
		ok "r3 kernel has an MFC entry for $GROUP"
	else
		fail "r3 kernel MFC is empty, pimd never pushed the route down"
	fi
	if has_mfc r1 "$GROUP"; then
		ok "r1 kernel has an MFC entry for $GROUP"
	else
		fail "r1 kernel MFC is empty"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# Every stream above is joined before it starts, which is the easy
	# order: the tree is up when the first packet is sent.  The other way
	# round is https://github.com/troglobit/pimd/issues/192 -- the DR
	# registers to an RP nobody is joined at, the RP stops it, and when
	# the receiver does join, the shared tree has to be built towards a
	# source whose Register-Stop already came.  A group of its own, so
	# none of the state above is what answers this.
	print "8. A receiver joining after the stream started is caught up"
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$STREAM_PKTS" -w 90 "$LATE_GROUP" \
		>"$WORKDIR/late-sender.log" 2>&1 &
	late_sender=$!
	sleep "$LATE_DELAY"
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 90 "$LATE_GROUP" \
		>"$WORKDIR/late-receiver.log" 2>&1 &
	late_receiver=$!
	wait "$late_sender" 2>/dev/null || true
	kill "$late_receiver" 2>/dev/null || true
	wait "$late_receiver" 2>/dev/null || true

	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/late-sender.log")
	replies=${replies:-0}
	if [ "$replies" -ge "$MIN_REPLIES" ]; then
		ok "ED2 joined $LATE_GROUP ${LATE_DELAY}s late and still got $replies of $STREAM_PKTS"
	else
		fail "only $replies replies for $LATE_GROUP, want >= $MIN_REPLIES, see $WORKDIR/late-sender.log"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in $ROUTERS; do
		dprint "--- $r: pimctl show pim detail ---"
		pimctl "$r" show pim detail 2>&1 | tail -40 || true
	done
	return 1
}


# Does router $1 hold an (S,G) for source $2 and group $3?  "show mrt"
# prints one row per entry, the source in the first column and "ANY" there
# for a (*,G), so this is the (S,G) half of has_mrt() and does not match a
# shared tree entry for the same group.
has_sg() {
	pimctl "$1" show mrt 2>/dev/null | \
		awk -v s="$2" -v g="$3" '$1 == s && $2 == g { found = 1 } END { exit !found }'
}

# Let ED1 send to the group with nobody listening.  mping counts replies and
# exits non-zero when it gets none, which here is the expected outcome.
regf_send() {
	box_run ed1 "$MPING" -s -i "${EP}101a" -t 5 -c "$REGF_PKTS" \
		-w $((REGF_PKTS + 20)) "$GROUP" >"$WORKDIR/sender.log" 2>&1 || true
}

# register-filter: the Register filter of RFC 7761 sec. 6.2, which is A3 in
# doc/rfc7761-compliance.md.  R2 is the RP and starts with a
# "register-accept-from" that does not cover the address R1 registers from,
# so every Register it sends is refused; then the prefix is replaced with one
# that does cover it and the same traffic is sent again.  The second half is
# there because the first on its own proves nothing: a router that never
# registered, or an RP that never heard it, leaves exactly the same empty
# table as a filter that is working.
#
# The two halves are compared on the Register-Stop, and on whether the DR
# still has the register vif in the oif list of the entry.  Not on the RP's
# table: A3's own Test note
# proposed "a pimctl show mrt on the RP with no (S,G) in it" and that cannot
# be had.  The RP holds entries for the group whether it accepted the
# Register or refused it, because the kernel decapsulates first -- and a
# shared tree is waiting for the inner packets even with nobody listening,
# send_pim_register() (src/pim_proto.c) firing the Join/Prune timer of the
# group entry as it registers, so the DR joins the tree it registers to.
# Assertion 7 asserts that state rather than working around it: it is A3,
# and a kernel that ever filtered before decapsulating should fail there and
# have the entry rewritten.
#
# Nobody joins the group all the same, which keeps R3 and the receiver out
# of the RP's table and the run down to the two routers it is about.
check_register_filter() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	# Before a packet moves: a pimd that parsed the keyword and threw the
	# prefix away would refuse nothing and pass every assertion below by
	# accident.  dump_reg_acl() (src/config.c) prints the list only when
	# there is one, so the line existing is half the answer.
	print "2. The RP has the filter, and the domain has the RP"
	if pimctl r2 show status 2>/dev/null | grep -q "Register accept list *: *$REGF_DENY"; then
		ok "r2: accepting Registers from $REGF_DENY and nowhere else"
	else
		fail "r2: 'show status' has no 'Register accept list : $REGF_DENY'"
		return 1
	fi
	if wait_for 90 has_rp r1 "$RP_ADDR"; then
		ok "r1 learned RP $RP_ADDR, so it has somewhere to register"
	else
		fail "r1 never learned RP $RP_ADDR (BSR/cand-RP path)"
		return 1
	fi

	print "3. The source sends and the DR encapsulates"
	dprint "sending $REGF_PKTS packets to $GROUP with nobody listening ..."
	regf_send
	if has_sg r1 "$SRC_ADDR" "$GROUP"; then
		ok "r1 has ($SRC_ADDR,$GROUP), the entry it registers for"
	else
		fail "r1 has no ($SRC_ADDR,$GROUP), the sender never reached its DR"
		return 1
	fi
	# The register vif in the oif list is what a DR encapsulating to the RP
	# looks like from the outside: process_cache_miss() (src/route.c) puts
	# PIMREG_VIF there for a directly connected source whose RP is somebody
	# else, and every packet then leaves by it.  Asked of the entry rather
	# than of the log, because the "Send PIM REGISTER" line sits inside the
	# MRTF_NEW arm of send_pim_register() and a cache miss has already
	# cleared that flag by the time the first Register goes out.
	if [ "$(route_oifs r1 "$SRC_ADDR" "$GROUP" | cut -c1)" = "o" ]; then
		ok "r1 forwards ($SRC_ADDR,$GROUP) out the register vif"
	else
		fail "r1 has no register vif in the oifs of ($SRC_ADDR,$GROUP), it never encapsulated"
		return 1
	fi

	print "4. The RP refuses every one of them"
	if logged r2 "PIM register from $REGF_SENDER: sender not in the register-accept-from list"; then
		ok "r2 refused Registers from $REGF_SENDER, outside $REGF_DENY"
	else
		fail "r2 logged no refusal for $REGF_SENDER, the filter let them through"
	fi

	# The address the RP matched is the one this scenario is shaped
	# around: R1 has 10.0.12.1 on the link to the RP, inside $REGF_DENY,
	# and registers from $REGF_SENDER, outside it.  A pimd that matched
	# the wrong one accepts here and assertion 6 is what says so.
	if logged r2 "PIM register from 10.0.12.1"; then
		fail "r2 matched R1's address on the RP link, not the one it registered from"
	else
		ok "r2 matched the Register's own source address"
	fi

	print "5. The kernel opened them regardless, which is what A3 is about"
	rcvd=$(registers_rcvd r2)
	rcvd=${rcvd:-0}
	if [ "$rcvd" -gt 0 ]; then
		ok "r2's kernel took in and decapsulated $rcvd Register(s) pimd refused"
	else
		fail "r2's kernel counted no Registers at all, nothing reached the RP"
		return 1
	fi

	print "6. And the RP answers nothing"
	# Withheld on purpose: answering a sender outside the list tells a
	# forger it found the RP, see receive_pim_register() (src/pim_proto.c).
	if logged r1 "Received PIM_REGISTER_STOP"; then
		fail "r1 got a Register-Stop, the RP answered a sender it had refused"
	else
		ok "r1 got no Register-Stop back"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# A3 itself, and the reason this scenario does not assert an empty
	# table on the RP the way doc/rfc7761-compliance.md once suggested it
	# could.  The RP holds entries for the group although it refused every
	# Register that named it: the kernel counted in assertion 5 handed the
	# inner packets to the register vif, and process_cache_miss()
	# (src/route.c) made of them what it makes of any traffic arriving on
	# an incoming interface it has a route for.  A kernel that filtered
	# before decapsulating would fail this, and A3 would be the entry that
	# needed rewriting, not the scenario.
	print "7. The state the filter cannot refuse is there all the same"
	if has_mrt r2 "$GROUP"; then
		ok "r2 holds $(pimctl r2 show mrt 2>/dev/null | awk -v g="$GROUP" '$2 == g { print $1 }' | tr '\n' ' ')for $GROUP, built from the decapsulated packets"
		dprint "A3: the filter refuses the state a Register makes, never the packet"
	else
		fail "r2 has no $GROUP entry at all, the kernel no longer decapsulates a refused Register"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# Everything above is an absence, and an absence is what a lab that
	# quietly did nothing also produces.  The same three routers, the same
	# stream, one prefix changed.
	print "8. The prefix is replaced with one that covers the sender"
	sed "s|^register-accept-from .*|register-accept-from $REGF_ACCEPT|" \
		"$WORKDIR/r2.conf" > "$WORKDIR/r2.conf.new" && \
		mv "$WORKDIR/r2.conf.new" "$WORKDIR/r2.conf" || \
		die "failed rewriting $WORKDIR/r2.conf"
	pimctl r2 restart >/dev/null 2>&1 || die "failed reloading pimd on r2"
	if wait_for 60 regf_acl_is r2 "$REGF_ACCEPT"; then
		ok "r2: accepting Registers from $REGF_ACCEPT after the reload"
	else
		fail "r2: 'show status' still reads '$(pimctl r2 show status 2>/dev/null | sed -n 's/^Register accept list *: *//p')'"
		return 1
	fi
	# restart() (src/main.c) tears the RP and BSR state down with
	# everything else, so R1 has to be given time to learn the RP again
	# before it has anywhere to register to.
	if wait_for 90 has_rp r1 "$RP_ADDR"; then
		ok "r1 learned RP $RP_ADDR again"
	else
		fail "r1 never got the RP set back after r2 reloaded"
		return 1
	fi

	# Two things have to be true before these Registers can be answered,
	# and neither is when R2 answers pimctl again.  R2 is not the RP for
	# $GROUP until its own Cand-RP-Advertisement has rebuilt the RP set
	# restart() dropped, up to an interval later, and a Register reaching
	# it meanwhile gets the Register-Stop sec. 4.4.2 sends for a group the
	# receiver is not the RP of.  The last packet of step 3's stream can be
	# that Register: the reload comes the moment regf_send returns.  R1 then
	# holds off for Register_Suppression_Time, a random 30 to 90 seconds,
	# longer than the stream below, so the stream went mostly or wholly
	# unregistered, and the Register-Stop this step looked for was that
	# one.  R1 still holding the old RP set says nothing about either, so
	# this waits on R2 taking the role back and on R1 registering again,
	# and counts Register-Stops from there.
	print "9. The same Registers are now acted on"
	if ! wait_for 60 regf_is_rp r2; then
		fail "r2 never took the RP role for $GROUP back after the reload"
		return 1
	fi
	if ! wait_for "$REGF_SUPP_WAIT" register_oif_present r1 "$SRC_ADDR" "$GROUP"; then
		fail "r1 did not register ($SRC_ADDR,$GROUP) again in ${REGF_SUPP_WAIT}s of the reload"
		return 1
	fi
	stops=$(register_stops r1)
	dprint "sending another $REGF_PKTS packets to $GROUP ..."
	regf_send &
	regf_sender=$!
	if wait_for 60 register_stops_above r1 "$stops"; then
		ok "r1 got a Register-Stop for this stream"
	else
		fail "r1 got no Register-Stop, the RP accepted but never answered"
		wait "$regf_sender"
		return 1
	fi
	# The DR acting on it, which is what tells a Register-Stop that arrived
	# from one that was merely logged, and the mirror of assertion 3:
	# suppress_register() (src/pim_proto.c) prunes PIMREG_VIF, so the vif
	# that was in the oif list while the RP refused leaves it once the RP
	# answers.  Asked while the stream still runs, and of the oif list and
	# not of the Register-Suppression timer beside it: that timer is at
	# least 30 seconds from the Register-Stop just counted, where asking
	# after the stream had ended could meet it run out.
	if wait_for 10 register_oif_gone r1 "$SRC_ADDR" "$GROUP"; then
		ok "r1 dropped the register vif from ($SRC_ADDR,$GROUP), it stopped encapsulating"
	else
		fail "r1 still forwards ($SRC_ADDR,$GROUP) out the register vif, the Register-Stop changed nothing"
	fi
	wait "$regf_sender"

	result
}

# One of the three timers "show mrt detail" prints per entry, by position:
# 1 is the entry timer, 2 the Join/Prune timer, 3 the Register-Suppression
# one.  They sit on the line after the TIMERS header.
route_timer() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" -v n="$4" '
		$1 == s && $2 == g { want = 1; next }
		want && /^TIMERS/  { hdr = 1; next }
		hdr		   { print $n; exit }
	'
}

# The largest per-vif timer of ($2,$3) on $1, off the same line: which vif
# holds it does not matter here, only that the Join raised one and that it
# is still where the message put it.
route_vif_timer() {
	pimctl "$1" show mrt detail 2>/dev/null | awk -v s="$2" -v g="$3" '
		$1 == s && $2 == g { want = 1; next }
		want && /^TIMERS/  { hdr = 1; next }
		hdr { max = 0; for (i = 4; i <= NF; i++) if ($i + 0 > max) max = $i + 0; print max; exit }
	'
}

# The RP address "show mrt" prints for ($2,$3) on router $1
route_rp() {
	pimctl "$1" show mrt 2>/dev/null | awk -v s="$2" -v g="$3" '$1 == s && $2 == g { print $3; exit }'
}

route_rp_is() { [ "$(route_rp "$1" "$2" "$3")" = "$4" ]; }

# Both timers the Join/Prune holdtime raises, still at the sentinel
route_held() {
	[ "$(route_timer "$1" "$2" "$3" 1)" = "65535" ] && 		[ "$(route_vif_timer "$1" "$2" "$3")" = "65535" ]
}

# For wait_for(): has the register vif left the oif list of ($2,$3) on $1?
# Position 0 of the "Outgoing oifs" map is PIMREG_VIF, see route_oifs().
register_oif_gone() {
	[ "$(route_oifs "$1" "$2" "$3" | cut -c1)" != "o" ]
}
register_oif_present() {
	[ "$(route_oifs "$1" "$2" "$3" | cut -c1)" = "o" ]
}

# Register-Stops router $1 has received so far, and for wait_for(), whether
# that is more than $2
register_stops() {
	${SUDO} grep -c "Received PIM_REGISTER_STOP" "$WORKDIR/$1.log" 2>/dev/null || true
}
register_stops_above() { [ "$(register_stops "$1")" -gt "$2" ]; }

# Is router $1 the RP of $GROUP by its own RP set?
regf_is_rp() {
	pimctl "$1" show rp 2>/dev/null | grep -q "$RP_ADDR"
}

# The register-accept-from list r2 is running with, for wait_for(): a
# reload has to be given time to land, and "show status" is where the
# running list shows.
regf_acl_is() {
	pimctl "$1" show status 2>/dev/null | \
		grep -q "Register accept list *: *$2"
}



# anycast: RFC 4610, Anycast-RP using PIM.  R2 and R3 both hold $ANY_ADDR,
# the RP of every group.  R1 registers to R2, because that is where its
# route to the address goes, and ED2's shared tree ends at R3, which is
# the RP for ED2's LAN as well as its DR.  Two RPs that do not know of each
# other split the domain in two there: the source is known to R2 only and
# the receiver to R3 only.  An Anycast-RP set joins them up again, R2
# copying to R3 every Register it takes from R1.
#
# Every assertion about the copy is read off the two routers' logs, the
# "Copy PIM Register" line R2 writes as it sends one and the "Received PIM
# register" line R3 writes when it arrives, TTL included.  That is two pimds
# agreeing, the weakness the header of this file names, and the traffic at
# the end is what does not depend on it.
check_anycast() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. Both RPs hold $ANY_ADDR, and R1 has it for its RP"
	for r in r2 r3; do
		if pimctl "$r" show interface 2>/dev/null | grep -q "$ANY_ADDR"; then
			ok "$r has a VIF on $ANY_ADDR, the anycast address on $LOOPBACK_IF"
		else
			fail "$r has no VIF on $ANY_ADDR, it cannot be the RP for it"
		fi
	done
	if wait_for 30 has_static_rp r1 "$ANY_ADDR"; then
		ok "r1 registers to $ANY_ADDR"
	else
		fail "r1 has no static RP $ANY_ADDR"
	fi
	if wait_for 60 has_neighbor r3 "$ANY_R2" && wait_for 60 has_neighbor r2 10.0.12.1; then
		ok "r3 and r2 have the neighbours their Joins toward the source need"
	else
		fail "the R1-R2-R3 chain has no PIM neighbours"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# The control, and it has to be one.  A set that did nothing would
	# leave exactly this, so the source has to be seen to register to R2,
	# or the silence at ED2 below would be a lab that never registered.
	print "3. Without a set, a receiver behind R3 hears nothing of the source"
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 90 "$GROUP" \
		>"$WORKDIR/anycast-control-receiver.log" 2>&1 &
	receiver=$!
	sleep 5
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c 20 -w 30 "$GROUP" \
		>"$WORKDIR/anycast-control-sender.log" 2>&1 || true
	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true
	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/anycast-control-sender.log")
	if logged r2 "Received PIM register: .* from $ANY_DR"; then
		ok "r2 was sent the source's Registers"
	else
		fail "r2 got no Register from $ANY_DR, the control proves nothing"
		return 1
	fi
	if [ "${replies:-0}" -eq 0 ] && ! has_sg r3 "$SRC_ADDR" "$GROUP"; then
		ok "ed2 got nothing and r3 never heard of $SRC_ADDR, two RPs with no set"
	else
		fail "ed2 answered ${replies:-0} packet(s) or r3 has ($SRC_ADDR,$GROUP) with no set configured"
		return 1
	fi

	print "4. R2 and R3 are made one Anycast-RP set"
	for r in r2 r3; do
		printf 'anycast-rp %s %s\nanycast-rp %s %s\n' "$ANY_ADDR" "$ANY_R2" "$ANY_ADDR" "$ANY_R3" \
			>> "$WORKDIR/$r.conf"
		pimctl "$r" restart >/dev/null 2>&1 || die "failed reloading pimd on $r"
	done
	if wait_for 30 anycast_member_is r2 "$ANY_R2" && wait_for 30 anycast_member_is r3 "$ANY_R3"; then
		ok "r2 is member $ANY_R2 and r3 member $ANY_R3 of the set for $ANY_ADDR"
	else
		fail "'show status' has no Anycast-RP set naming each router's own member"
		return 1
	fi
	# restart() (src/main.c) rebuilds the VIFs and the neighbours with them
	if wait_for 60 has_neighbor r3 "$ANY_R2" && wait_for 60 has_neighbor r2 10.0.12.1; then
		ok "the neighbours are back after the reload"
	else
		fail "r2 or r3 did not get its neighbours back after the reload"
		return 1
	fi

	print "5. A source registering to R2 is copied to R3"
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c $((ANY_REFRESH + 120)) -w $((ANY_REFRESH + 150)) \
		"$ANY_GROUP" >"$WORKDIR/anycast-sender.log" 2>&1 &
	sender=$!
	copy="Copy PIM Register from $ANY_DR for ($SRC_ADDR, $ANY_GROUP) to Anycast-RP member $ANY_R3"
	if wait_for 30 logged r2 "$copy"; then
		ok "r2 copied the Register for ($SRC_ADDR,$ANY_GROUP) to $ANY_R3"
	else
		fail "r2 sent $ANY_R3 no copy of the Registers for ($SRC_ADDR,$ANY_GROUP)"
		kill "$sender" 2>/dev/null || true
		return 1
	fi
	# A copy is what the kernel handed pimd of the Register.  FreeBSD's
	# pim_input() hands up the headers of a data Register, so a copy there
	# can only be a Null-Register; Linux hands up the whole packet, and the
	# copy is a data Register.  The other kind here would mean the kernel
	# changed, and the man page's deviation would want rewriting.
	if [ "$REGISTER_UPCALL" = headers ]; then
		want=null
		other=data
	else
		want=data
		other=null
	fi
	if logged r2 "$copy, TTL [0-9]*, $want" && ! logged r2 "$copy, TTL [0-9]*, $other"; then
		ok "every copy is a $want Register, the kernel gave r2 the $REGISTER_UPCALL of it"
	else
		fail "r2 copied a $other Register, the kernel was expected to hand it the $REGISTER_UPCALL of one"
	fi
	if wait_for 30 has_sg r3 "$SRC_ADDR" "$ANY_GROUP"; then
		ok "r3 holds ($SRC_ADDR,$ANY_GROUP) with nobody joined, RFC 4610 sec. 3"
	else
		fail "r3 has no ($SRC_ADDR,$ANY_GROUP), the copy made no state"
	fi

	# ... and the same fact read at the receiving end, off the wire rather
	# than off what r2 said it sent
	if ! wait_for 60 anycast_reglen_seen r3 "$ANY_R2"; then
		fail "r3 logged no Register from $ANY_R2 to measure"
	else
		len=$(anycast_reglen r3 "$ANY_R2")
		if [ "$REGISTER_UPCALL" = headers ] && [ "$len" -eq "$REG_NULL_LEN" ]; then
			ok "no copy r3 was handed was longer than $len bytes, the header alone"
		elif [ "$REGISTER_UPCALL" = whole ] && \
		     wait_for 60 anycast_reglen_above r3 "$ANY_R2" "$REG_NULL_LEN"; then
			ok "r3 was handed $(anycast_reglen r3 "$ANY_R2") bytes, more than the $REG_NULL_LEN of a Null-Register"
		else
			fail "the longest copy r3 was handed is $len bytes, expected the $REGISTER_UPCALL of a data Register"
		fi
	fi

	print "6. The copy carries one less TTL than the Register it copies"
	ttl_in=$(anycast_ttl r2 "$ANY_DR")
	ttl_out=$(anycast_ttl r3 "$ANY_R2")
	if [ -n "$ttl_in" ] && [ -n "$ttl_out" ] && [ "$ttl_out" -eq $((ttl_in - 1)) ]; then
		ok "r2 was sent TTL $ttl_in, r3 was sent the copy at TTL $ttl_out"
	else
		fail "r2 was sent TTL '${ttl_in}', r3 the copy at TTL '${ttl_out}'"
	fi

	print "7. R3 does not copy on what it was copied"
	if logged r3 "Received PIM register: .* from $ANY_R2" && ! logged r3 "Copy PIM Register"; then
		ok "r3 took the copies from $ANY_R2 and sent none of its own"
	else
		fail "r3 copied a Register it was sent by another member, or never got one"
	fi
	[ "$FAILED" -eq 0 ] || { kill "$sender" 2>/dev/null || true; return 1; }

	# The DR probes with a Null-Register once R2 has stopped it, 25 to 85
	# seconds apart, and those are copied too.  Nothing else reaches R3
	# about this source while nobody there has joined, so the (S,G) only
	# outlives PIM_DATA_TIMEOUT if the copies keep refreshing it.
	print "8. With nobody joined, R3 keeps the source for ${ANY_REFRESH}s on the copies alone"
	before=$(anycast_copies r2)
	elapsed=0
	lost=
	while [ "$elapsed" -lt "$ANY_REFRESH" ]; do
		if ! has_sg r3 "$SRC_ADDR" "$ANY_GROUP"; then
			lost=$elapsed
			break
		fi
		sleep 5
		elapsed=$((elapsed + 5))
	done
	after=$(anycast_copies r2)
	if [ -z "$lost" ]; then
		ok "r3 held ($SRC_ADDR,$ANY_GROUP) for ${ANY_REFRESH}s"
	else
		fail "r3 lost ($SRC_ADDR,$ANY_GROUP) after ${lost}s"
	fi
	if [ "${after:-0}" -gt "${before:-0}" ]; then
		ok "r2 sent $((after - before)) more copies meanwhile, the probes being copied"
	else
		fail "r2 sent no copy in ${ANY_REFRESH}s, nothing refreshed r3"
	fi

	print "9. A receiver joining at R3 gets the source's traffic"
	if box_run ed2 timeout 90 "$MPING" -r -i "$ED2_IF" -t 5 -c 5 "$ANY_GROUP" \
		>"$WORKDIR/anycast-receiver.log" 2>&1; then
		ok "ed2 received 5 packets from $SRC_ADDR through r3"
	else
		fail "ed2 received fewer than 5 packets in 90s"
	fi
	iif=$(route_iif r3 "$SRC_ADDR" "$ANY_GROUP")
	if [ -n "$iif" ] && [ "$iif" -ne 0 ]; then
		ok "r3's ($SRC_ADDR,$ANY_GROUP) comes in on vif $iif, the source tree, not the register vif"
	else
		fail "r3's ($SRC_ADDR,$ANY_GROUP) has iif '${iif}'"
	fi
	kill "$sender" 2>/dev/null || true
	wait "$sender" 2>/dev/null || true

	# RFC 4610 leaves rate limiting to the DR, and whoever sends Registers
	# to the anycast address need not be one.  One process sends the whole
	# burst, pimsend -c: one per packet is far too slow to cross the limit.
	# A Register whose inner packet is an IP header alone is one FreeBSD
	# hands pimd whole, so its copies start out as data copies.
	print "10. A burst of Registers is copied only up to the budget"
	box_run ed1 "$PIMSEND" -i "$SRC_ADDR" register -d "$ANY_ADDR" -g "$ANY_BURST_GROUP" \
		-s "$ANY_BURST_SRC" -c "$ANY_BURST" >/dev/null 2>&1 || true
	sleep 3
	burst="Copy PIM Register from $SRC_ADDR for ($ANY_BURST_SRC, $ANY_BURST_GROUP) to Anycast-RP member $ANY_R3"
	data=$(${SUDO} grep -c "$burst, TTL [0-9]*, data" "$WORKDIR/r2.log" 2>/dev/null || true)
	null=$(${SUDO} grep -c "$burst, TTL [0-9]*, null" "$WORKDIR/r2.log" 2>/dev/null || true)
	data=${data:-0}
	null=${null:-0}
	# The budget is per second and a burst may straddle two, hence twice
	if [ "$data" -ge 1 ] && [ "$data" -le 128 ] && [ "$null" -ge 1 ]; then
		ok "r2 copied $data whole and then $null as Null-Registers, the data budget is 64 a second"
	else
		fail "r2 copied $data whole and $null as Null-Registers from a burst of $ANY_BURST"
	fi
	if [ $((data + null)) -le 512 ] && logged r2 "Anycast-RP copies over 256 per second"; then
		ok "r2 copied $((data + null)) of $ANY_BURST and said it stopped at 256 a second"
	else
		fail "r2 copied $((data + null)) of $ANY_BURST, or never said it hit the copy budget"
	fi

	# The Registers name sources one at a time, as a Register from anywhere
	# can.  R2 is full already: the steps above left it an entry for every
	# source registered to it, ED2 answering among them.  A reload frees
	# them, which is also the check that the count is given back, and the
	# probes still arriving can take a slot again before the six do, so what
	# is asserted is that some of the six fit and some do not.
	print "11. Registers make no more state than register-sg-limit allows"
	pimctl r2 restart >/dev/null 2>&1 || die "failed reloading pimd on r2"
	wait_for 30 anycast_member_is r2 "$ANY_R2" || true
	# The reload drops the neighbours too, and pimd makes no (S,G) for a
	# source whose next hop is not a PIM neighbour, limit or none
	wait_for 60 has_neighbor r2 10.0.12.1 || true
	count=$(pimctl r2 show status 2>/dev/null | sed -n 's/^Register (S,G) state *: *\([0-9]*\) of .*/\1/p')
	if [ -n "$count" ] && [ "$count" -lt "$ANY_SG_LIMIT" ]; then
		ok "r2 counts $count Register (S,G) entries after a reload, the count was given back"
	else
		fail "r2 counts '$count' Register (S,G) entries after a reload"
	fi
	for i in 101 102 103 104 105 106; do
		box_run ed1 "$PIMSEND" -i "$SRC_ADDR" register -d "$ANY_ADDR" -g "$ANY_LIMIT_GROUP" \
			-s "10.0.1.$i" -N >/dev/null 2>&1 || true
	done
	sleep 2
	held=0
	for i in 101 102 103 104 105 106; do
		has_sg r2 "10.0.1.$i" "$ANY_LIMIT_GROUP" && held=$((held + 1))
	done
	count=$(pimctl r2 show status 2>/dev/null | sed -n 's/^Register (S,G) state *: *\([0-9]*\) of .*/\1/p')
	if [ "$held" -ge 1 ] && [ "$held" -lt 6 ] && logged r2 "register-sg-limit $ANY_SG_LIMIT reached"; then
		ok "r2 holds $held of 6 sources, and said it reached register-sg-limit $ANY_SG_LIMIT"
	else
		fail "r2 holds $held of 6 sources under register-sg-limit $ANY_SG_LIMIT"
	fi
	if [ -n "$count" ] && [ "$count" -le "$ANY_SG_LIMIT" ]; then
		ok "r2 counts $count Register (S,G) entries of $ANY_SG_LIMIT"
	else
		fail "r2 counts '$count' Register (S,G) entries against a limit of $ANY_SG_LIMIT"
	fi

	# Step 5 asked what kind of copy had crossed as soon as one had, which
	# on the headers side is only ever "nothing longer than a header has
	# arrived *yet*": a data copy appearing later, once the kernel started
	# handing pimd whole Registers, would have come after the question.
	# Every copy of the whole scenario has been sent by now, so ask again.
	print "12. No copy contradicted the kernel's upcall for the whole run"
	len=$(anycast_reglen r3 "$ANY_R2")
	if [ -z "$len" ]; then
		fail "r3 logged no Register from $ANY_R2 at all"
	elif [ "$REGISTER_UPCALL" = headers ] && [ "$len" -eq "$REG_NULL_LEN" ]; then
		ok "the longest of them is still $len bytes, the header alone"
	elif [ "$REGISTER_UPCALL" = whole ] && [ "$len" -gt "$REG_NULL_LEN" ]; then
		ok "the longest of them is $len bytes, a Register that crossed whole"
	else
		fail "the longest copy r3 was handed is $len bytes, which is not the $REGISTER_UPCALL of a data Register"
	fi

	result
}

# anycast-dr: RFC 4610 sec. 5.1, an Anycast-RP member that is the DR of the
# source as well as its RP.  R1 is sent no Register for the source -- it
# would be sending it to itself -- so there is nothing to copy, and before
# this R3 never heard of the source at all.  R1 has to register it to the
# rest of the set itself: process_cache_miss() (src/route.c) puts the
# register vif in the oifs, and send_pim_register() sends the Register to
# each other member from R1's own member address rather than to the RP.
#
# The Register is a data Register on FreeBSD too, unlike anycast's copies:
# what R1 encapsulates comes from the kernel's upcall for the packet, which
# holds all of it, not from a Register the kernel had already opened.
check_anycast_dr() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. R1 and R3 hold $ANY_ADDR, and R2 has it for its RP"
	for r in r1 r3; do
		if pimctl "$r" show interface 2>/dev/null | grep -q "$ANY_ADDR"; then
			ok "$r has a VIF on $ANY_ADDR, the anycast address on $LOOPBACK_IF"
		else
			fail "$r has no VIF on $ANY_ADDR, it cannot be the RP for it"
		fi
	done
	if wait_for 30 has_static_rp r2 "$ANY_ADDR"; then
		ok "r2 has $ANY_ADDR for its RP"
	else
		fail "r2 has no static RP $ANY_ADDR"
	fi
	if wait_for 60 has_neighbor r3 "$ANY_R2" && wait_for 60 has_neighbor r2 "$ANYDR_R1"; then
		ok "r3 and r2 have the neighbours their Joins toward the source need"
	else
		fail "the R1-R2-R3 chain has no PIM neighbours"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# R1 being the RP, nothing at all is registered without a set: the
	# control has to show the source reached R1, or the silence is a lab
	# that never sent.
	print "3. Without a set, a receiver behind R3 hears nothing of the source"
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 90 "$GROUP" \
		>"$WORKDIR/anycast-dr-control-receiver.log" 2>&1 &
	receiver=$!
	sleep 5
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c 20 -w 30 "$GROUP" \
		>"$WORKDIR/anycast-dr-control-sender.log" 2>&1 || true
	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true
	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/anycast-dr-control-sender.log")
	if has_sg r1 "$SRC_ADDR" "$GROUP"; then
		ok "r1 has ($SRC_ADDR,$GROUP), the source reached its DR"
	else
		fail "r1 has no ($SRC_ADDR,$GROUP), the control proves nothing"
		return 1
	fi
	if [ "${replies:-0}" -eq 0 ] && ! has_sg r3 "$SRC_ADDR" "$GROUP" && \
		! logged r1 "Send PIM Register for"; then
		ok "r1 registered nothing, ed2 got nothing and r3 never heard of $SRC_ADDR"
	else
		fail "with no set, ed2 answered ${replies:-0} packet(s), or r3 has the source, or r1 registered it"
		return 1
	fi

	print "4. R1 and R3 are made one Anycast-RP set"
	for r in r1 r3; do
		printf 'anycast-rp %s %s\nanycast-rp %s %s\n' "$ANY_ADDR" "$ANYDR_R1" "$ANY_ADDR" "$ANY_R3" \
			>> "$WORKDIR/$r.conf"
		pimctl "$r" restart >/dev/null 2>&1 || die "failed reloading pimd on $r"
	done
	if wait_for 30 anycast_member_is r1 "$ANYDR_R1" && wait_for 30 anycast_member_is r3 "$ANY_R3"; then
		ok "r1 is member $ANYDR_R1 and r3 member $ANY_R3 of the set for $ANY_ADDR"
	else
		fail "'show status' has no Anycast-RP set naming each router's own member"
		return 1
	fi
	if wait_for 60 has_neighbor r3 "$ANY_R2" && wait_for 60 has_neighbor r2 "$ANYDR_R1"; then
		ok "the neighbours are back after the reload"
	else
		fail "r2 or r3 did not get its neighbours back after the reload"
		return 1
	fi

	print "5. R1 registers its own source to R3, from its member address"
	stops=$(register_stops r1)
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c 180 -w 210 "$ANY_GROUP" \
		>"$WORKDIR/anycast-dr-sender.log" 2>&1 &
	sender=$!
	reg="Send PIM Register for ($SRC_ADDR, $ANY_GROUP) to Anycast-RP member $ANY_R3"
	if wait_for 30 logged r1 "$reg, data"; then
		ok "r1 sent $ANY_R3 a data Register for ($SRC_ADDR,$ANY_GROUP)"
	else
		fail "r1 sent $ANY_R3 no data Register for ($SRC_ADDR,$ANY_GROUP)"
		kill "$sender" 2>/dev/null || true
		return 1
	fi
	# A data Register on the wire, which R3's pimd cannot say: FreeBSD hands
	# it the headers of any data Register, 28 bytes, see anycast step 5.
	# pim_input() counts what it decapsulates, and that counter can, while
	# the log says who it came from and at what TTL -- one less than R1 sent
	# it at, R2 having routed it.
	rcvd=$(registers_rcvd r3)
	got=$(${SUDO} grep "Received PIM register: .* from $ANYDR_R1" "$WORKDIR/r3.log" 2>/dev/null | \
		sed -n '1s/.* ttl = \([0-9]*\) .*/\1/p')
	if [ "${rcvd:-0}" -gt 0 ] && [ -n "$got" ]; then
		ok "r3's kernel decapsulated ${rcvd} data Register(s), and pimd logged $ANYDR_R1 sending at TTL $got"
	else
		fail "r3's kernel counted ${rcvd:-0} data Register(s), pimd logged TTL '$got' from $ANYDR_R1"
	fi
	if wait_for 30 has_sg r3 "$SRC_ADDR" "$ANY_GROUP" && ! logged r3 "Copy PIM Register"; then
		ok "r3 holds ($SRC_ADDR,$ANY_GROUP) and copied the Register nowhere"
	else
		fail "r3 has no ($SRC_ADDR,$ANY_GROUP), or took R1's Register for one to copy"
	fi

	print "6. R1 honours R3's Register-Stop"
	if wait_for 30 register_stops_above r1 "$stops" && \
		logged r1 "Received PIM_REGISTER_STOP from RP $ANY_R3"; then
		ok "r1 got a Register-Stop from $ANY_R3"
	else
		fail "r1 got no Register-Stop from $ANY_R3"
	fi
	if wait_for 10 register_oif_gone r1 "$SRC_ADDR" "$ANY_GROUP"; then
		ok "r1 dropped the register vif from ($SRC_ADDR,$ANY_GROUP), a member's Register-Stop is acted on"
	else
		fail "r1 still registers ($SRC_ADDR,$ANY_GROUP), it ignored the member's Register-Stop"
	fi

	# Register_Suppression_Time is 30 to 90 seconds and the probe goes out
	# 5 before it ends, so one is due within REGF_SUPP_WAIT.
	print "7. And probes R3 with a Null-Register while suppressed"
	if wait_for "$REGF_SUPP_WAIT" logged r1 "$reg, null"; then
		ok "r1 sent $ANY_R3 a Null-Register for ($SRC_ADDR,$ANY_GROUP)"
	else
		fail "r1 sent $ANY_R3 no Null-Register in ${REGF_SUPP_WAIT}s"
	fi

	print "8. A receiver joining at R3 gets the source's traffic"
	if box_run ed2 timeout 90 "$MPING" -r -i "$ED2_IF" -t 5 -c 5 "$ANY_GROUP" \
		>"$WORKDIR/anycast-dr-receiver.log" 2>&1; then
		ok "ed2 received 5 packets from $SRC_ADDR through r3"
	else
		fail "ed2 received fewer than 5 packets in 90s"
	fi
	iif=$(route_iif r3 "$SRC_ADDR" "$ANY_GROUP")
	if [ -n "$iif" ] && [ "$iif" -ne 0 ]; then
		ok "r3's ($SRC_ADDR,$ANY_GROUP) comes in on vif $iif, the source tree, not the register vif"
	else
		fail "r3's ($SRC_ADDR,$ANY_GROUP) has iif '${iif}'"
	fi
	kill "$sender" 2>/dev/null || true
	wait "$sender" 2>/dev/null || true

	# A member's Register-Stop is taken for the entries R1 registers to the
	# set, which step 6 is the positive control for, and for no other.  The
	# entry here R1 holds only because a member's Register made it, and a
	# Register-Stop acted on would still arm its Register-Suppression timer.
	print "9. A member's Register-Stop leaves an entry R1 does not register alone"
	box_run r3 "$PIMSEND" -i "$ANY_R3" register -d "$ANYDR_R1" -g "$ANYDR_STOP_GROUP" \
		-s "$ANYDR_STOP_SRC" -N >/dev/null 2>&1 || true
	if wait_for 10 has_sg r1 "$ANYDR_STOP_SRC" "$ANYDR_STOP_GROUP"; then
		ok "r1 holds ($ANYDR_STOP_SRC,$ANYDR_STOP_GROUP) from a member's Register, and registers nothing for it"
	else
		fail "r1 holds no ($ANYDR_STOP_SRC,$ANYDR_STOP_GROUP) after a member's Register"
		return 1
	fi
	box_run r3 "$PIMSEND" -i "$ANY_R3" regstop -d "$ANYDR_R1" -g "$ANYDR_STOP_GROUP" \
		-s "$ANYDR_STOP_SRC" >/dev/null 2>&1 || true
	if wait_for 10 logged r1 "Received PIM_REGISTER_STOP from RP $ANY_R3 to $ANYDR_R1 for src = $ANYDR_STOP_SRC"; then
		ok "r1 was sent the Register-Stop"
	else
		fail "r1 logged no Register-Stop for ($ANYDR_STOP_SRC,$ANYDR_STOP_GROUP)"
	fi
	rs=$(route_timer r1 "$ANYDR_STOP_SRC" "$ANYDR_STOP_GROUP" 3)
	if [ "${rs:-x}" = 0 ]; then
		ok "r1's Register-Suppression timer for it stayed at 0"
	else
		fail "r1 armed the Register-Suppression timer of an entry it does not register ('$rs')"
	fi

	result
}

# anycast: is $2 this router's own member in the set "show status" lists on $1?
anycast_member_is() {
	pimctl "$1" show status 2>/dev/null | \
		grep -q "^Anycast-RP set *: $ANY_ADDR, members .*$2 (this router)"
}

# anycast: how many Registers $1 has copied to $ANY_R3, off "show status"
anycast_copies() {
	pimctl "$1" show status 2>/dev/null | \
		sed -n "s/^Anycast-RP set.* $ANY_R3 (\([0-9]*\) copies).*/\1/p"
}

# anycast: the longest Register $1 logged receiving from $2.  A Register
# holding nothing but the inner IP header is 28 bytes, the PIM header and
# the header it encapsulates, so this is how the receiving end tells a copy
# of a data Register from a Null-Register -- what r2 logged copying says
# only what r2 believed it was sending.
#
# The longest rather than the first: the DR probes with a Null-Register
# while it is suppressed and those are copied too, so which kind arrives
# first is a race, and what the question is about is whether a data
# Register ever crosses whole.
anycast_reglen() {
	${SUDO} grep "Received PIM register: len = [0-9]* .* from $2" "$WORKDIR/$1.log" 2>/dev/null | \
		sed -n 's/.*len = \([0-9]*\) .*/\1/p' | sort -n | tail -1
}

anycast_reglen_seen()  { [ -n "$(anycast_reglen "$1" "$2")" ]; }
anycast_reglen_above() { [ "$(anycast_reglen "$1" "$2")" -gt "$3" ] 2>/dev/null; }

# anycast: the TTL of the first Register $1 logged receiving from $2
anycast_ttl() {
	${SUDO} grep "Received PIM register: .* ttl = [0-9]* from $2" "$WORKDIR/$1.log" 2>/dev/null | \
		sed -n '1s/.* ttl = \([0-9]*\) from .*/\1/p'
}

# static-rp: RFC 7761 sec. 4.7, "A PIM router MUST support the static
# configuration of group-to-RP mappings", against a domain that also has a
# BSR.  The two sources of a mapping share one list and one grp_mask_t, and
# the Bootstrap used to take the configured entry with it.
#
# The topology is rpt's and nothing is forwarded: every assertion is about
# what "pimctl show rp" holds on R3, which is the only router given an
# rp-address.
#
# $STATICRP_ADDR is R2's address on the R3 link, while the BSR advertises
# R2's address on the R1 link, so the two entries are the same router under
# two addresses.  They have to be different addresses or the scenario
# cannot tell what it is asking: add_rp_grp_entry() (src/rp.c) merges an
# advertisement for an RP and prefix it already holds into the existing
# entry, and a static entry that survived would be indistinguishable from
# one the BSR had just put back.
#
# An rp-address with no group covers 224.0.0.0/4 (src/config.c), which is
# the prefix r2.conf's "group-prefix 224.0.0.0 masklen 4" is advertised
# under, and that is the whole mechanism: one grp_mask_t, stamped with the
# Bootstrap's fragment tag, and a garbage collector at the end of
# receive_pim_bootstrap() that deletes every RP on a stamped prefix whose
# own tag differs.  The static entry never carried that tag.
#
# Step 5 is what the deviation cost in practice rather than on paper.  Only
# restart() reads g_rp_hold again (src/main.c), so a router that lost its
# configured RP this way did not get it back when the BSR died -- it aged
# the learned RP set out and was left with no RP at all until somebody sent
# it a SIGHUP.
check_static_rp() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. R3 starts with the RP its pimd.conf names"
	if wait_for 30 has_static_rp r3 "$STATICRP_ADDR"; then
		ok "r3 holds $STATICRP_ADDR as a static RP"
	else
		fail "r3 never installed $STATICRP_ADDR from rp-address, before any Bootstrap"
		return 1
	fi

	print "3. And then learns the BSR's RP beside it"
	if wait_for 90 has_dynamic_rp r3 "$RP_ADDR"; then
		ok "r3 learned $RP_ADDR from the bootstrap router"
	else
		fail "r3 never learned $RP_ADDR, the BSR path is not working and step 4 would prove nothing"
		return 1
	fi

	# The regression.  One Bootstrap for 224.0.0.0/4 was enough.
	print "4. The configured RP survived the Bootstrap"
	if has_static_rp r3 "$STATICRP_ADDR"; then
		ok "r3 still holds $STATICRP_ADDR, the garbage collector left it alone"
	else
		fail "r3 lost the RP from its own pimd.conf to a Bootstrap; sec. 4.7 requires it to be supported"
		return 1
	fi

	# What the deviation actually cost: a router with no RP at all.
	print "5. And outlives the bootstrap router"
	dprint "stopping the BSR and waiting for the learned RP to age out ..."
	[ -f "$WORKDIR/r2.pid" ] && ${SUDO} pkill -9 -F "$WORKDIR/r2.pid" 2>/dev/null
	if wait_for "$STATICRP_WAIT" no_dynamic_rp r3; then
		ok "r3 aged $RP_ADDR out once the BSR stopped"
	else
		fail "r3 still holds a dynamic RP after ${STATICRP_WAIT}s, the ageing never ran"
		return 1
	fi
	if has_static_rp r3 "$STATICRP_ADDR"; then
		ok "r3 is left with $STATICRP_ADDR, the RP it was configured with"
	else
		fail "r3 has no RP at all, which is what the deviation cost until a SIGHUP"
	fi

	result
}

# Has router $1 learned $2 from the bootstrap router, i.e. holds it with a
# holdtime rather than Forever?  The counterpart of has_static_rp().
has_dynamic_rp() {
	pimctl "$1" show rp 2>/dev/null | grep "$2" | grep -q Dynamic
}

# crafted: the checks that refuse a malformed message, driven by
# test/pimsend.c.  Every other scenario in this file has pimd on both ends,
# so the only messages pimd ever parses are messages pimd built, and a field
# it refuses to encode wrongly is a field nothing here can test it on.
# doc/rfc7761-compliance.md says so at the head of its packet format
# section, and this is the scenario that answers it.
#
# The topology is rpt's, with nobody joining the group and the traffic never
# started: nothing is forwarded here, the assertions are all about what R1
# does with a message handed to it.  ED1 is the sender, because ED1 is a
# host on a subnet R1 has a VIF on -- which is exactly the position
# RFC 7761 sec. 6.2 is about, and all an attacker needs.
#
# $CRAFT_ADDR is a second address on ED1 rather than its own, so that the
# scenario has one address that has said Hello and one that has not, at the
# same time, on the same link.  That pair is what tells a check that refuses
# a stranger from one that refuses everybody.
#
# What is guarded here, both fixed and both otherwise unreachable from a lab
# of pimds:
#
#   - the mask length bound of RFC 7761 sec. 4.9.1, in the Join/Prune and
#     Bootstrap parsers.  MASKLEN_TO_MASK() (src/pimd.h) shifts by
#     32 - masklen, so a byte above 32 shifted by a negative amount:
#     undefined behavior, and in practice a group range nobody advertised
#     over the domain's RP set.
#   - sec. 6.2's "SHOULD NOT accept protocol messages from a router from
#     which it has not yet received a valid Hello message", in the unicast
#     branch of receive_pim_bootstrap().
#
# Each has its positive control beside it.  A check that refuses everything
# passes every "was it refused?" assertion ever written, and the labs this
# file is made of cannot notice: nothing else here sends a Join or a
# Bootstrap that R1 would act on.
check_crafted() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	# The two addresses this scenario is built on.  Only the first says
	# Hello, so from here on R1 holds one neighbour on the link and one
	# stranger, both able to reach it.
	box_addr_add ed1 "${EP}101a" "$CRAFT_ADDR/24" 2>/dev/null || \
		die "failed adding $CRAFT_ADDR to ${EP}101a on ed1"
	craft "$SRC_ADDR" hello -H 105
	if wait_for 30 has_neighbor r1 "$SRC_ADDR"; then
		ok "r1 took $SRC_ADDR as a neighbour from one crafted Hello"
	else
		fail "r1 never saw the crafted Hello, pimsend is not reaching it"
		return 1
	fi
	if has_neighbor r1 "$CRAFT_ADDR"; then
		fail "r1 has $CRAFT_ADDR as a neighbour and nothing sent a Hello for it"
		return 1
	else
		ok "$CRAFT_ADDR is on the link and is nobody's neighbour"
	fi

	print "2. A Join/Prune carrying a mask length no address has is refused"
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$GROUP" -s "$CRAFT_SRC" -M "$CRAFT_BADLEN"
	if wait_for 10 logged r1 "source mask length $CRAFT_BADLEN is not 32"; then
		ok "r1 refused a Join whose source mask length is not 32"
	else
		fail "r1 acted on a source mask length of $CRAFT_BADLEN, sec. 4.9.1 says ignore the message"
	fi
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$GROUP" -s "$CRAFT_SRC" -m "$CRAFT_BADLEN"
	if wait_for 10 logged r1 "group mask length $CRAFT_BADLEN is wider than an address"; then
		ok "r1 refused a Join whose group mask length is wider than an address"
	else
		fail "r1 acted on a group mask length of $CRAFT_BADLEN"
	fi

	# The control.  Without it every assertion above is satisfied by a
	# parser that drops Join/Prunes altogether.
	print "3. And the same Join, correctly formed, is acted on"
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$GROUP" -s "$CRAFT_SRC"
	if wait_for 10 logged r1 "Received PIM JOIN/PRUNE from $SRC_ADDR"; then
		ok "r1 accepted a well-formed Join from $SRC_ADDR"
	else
		fail "r1 ignored a well-formed Join too, the checks refuse everything"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# sec. 4.9.5: a Join/Prune Holdtime of 0xffff has the receiver "hold
	# the state until canceled by the appropriate canceling Join/Prune
	# message".  Both timers the holdtime raises are asked, because
	# holding one and ageing the other is the state gone all the same --
	# which is what the first draft of this did, the entry timer counting
	# down under an outgoing interface that was held.
	#
	# No lab could reach this before pimsend: hello-interval accepts at
	# most 18724 seconds and 3.5 times that is 65534, one short of the
	# sentinel, so not even a configured pimd can advertise the value.
	#
	# It runs here, before the BSR is stopped, because an (S,G) Join is
	# acted on only where the RPF neighbour toward the source is a PIM
	# neighbour -- and the step below kills the one router upstream of
	# R1, which is that neighbour.
	print "4. A Join/Prune Holdtime of 0xffff is held, not aged"
	# An (S,G) needs a group entry, and a group entry needs an RP, so the
	# domain has to have converged before the Join can build anything.
	if ! wait_for 90 has_rp r1 "$RP_ADDR"; then
		fail "r1 never learned RP $RP_ADDR, nothing below can be asked"
		return 1
	fi
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$GROUP" -s "$CRAFT_FAR_SRC" -H 65535
	if ! wait_for 15 route_held r1 "$CRAFT_FAR_SRC" "$GROUP"; then
		fail "r1 built no ($CRAFT_FAR_SRC,$GROUP) with both timers at 65535, the Join was not acted on"
	else
		# Three timer intervals, so an unheld timer has moved
		dprint "waiting ${CRAFT_HOLD}s, a timer that ages loses ${CRAFT_HOLD}s in that time ..."
		sleep "$CRAFT_HOLD"
		if route_held r1 "$CRAFT_FAR_SRC" "$GROUP"; then
			ok "both timers still read 65535 after ${CRAFT_HOLD}s"
		else
			fail "r1 aged a holdtime of 0xffff: entry $(route_timer r1 "$CRAFT_FAR_SRC" "$GROUP" 1), oif $(route_vif_timer r1 "$CRAFT_FAR_SRC" "$GROUP")"
		fi
	fi

	# RFC 7761 sec. 4.5.4, T2 of doc/rfc7761-compliance.md: a router that
	# sees another router on its upstream interface send the Join(*,G) it
	# was about to send holds its own back, for t_suppressed or the HoldTime
	# of the Join it saw, whichever is shorter.  pimd computed the guards
	# and then set nothing, since 892acbe took the timer out after a loss
	# of multicast its report blamed on suppression lasting too long.
	#
	# The other router is $SUPP_ADDR, an address added to R2's end of the
	# R1-R2 link and driven by pimsend from R2's jail, so the Joins it sends
	# reach R1 exactly as a second downstream router's would.  R2 counts
	# what R1 sends it, off its own log, which is what makes the silence
	# asserted below R1's and not a lost message.  The control comes first:
	# R1 sends the periodic Join unprompted, or its not sending one says
	# nothing.  Step 6 is the bound 892acbe was missing, and why removing
	# suppression was not the fix: a Join with a short HoldTime keeps the
	# upstream's state only that long, so it must not keep R1 quiet longer.
	#
	# Here, before step 14, because a group needs an RP that step 14's
	# Bootstrap starts ageing out.
	print "5. A Join overheard on the upstream link holds back our own"
	box_addr_add r2 "${EPU}112b" "$SUPP_ADDR/24" 2>/dev/null || \
		die "failed adding $SUPP_ADDR to ${EPU}112b on r2"
	craft_on r2 "$SUPP_ADDR" hello -H 105
	if ! wait_for 30 has_neighbor r1 "$SUPP_ADDR"; then
		fail "r1 never took $SUPP_ADDR as a neighbour on its link to r2"
		return 1
	fi
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$SUPP_GROUP" -w -r "$RP_ADDR" -H 65535
	if ! wait_for 30 has_mrt r1 "$SUPP_GROUP"; then
		fail "r1 built no (*,$SUPP_GROUP) from the downstream Join"
		return 1
	fi
	n=$(r1_wc_joins)
	if wait_for $((SUPP_PERIOD + 15)) r1_wc_joins_above "$n"; then
		ok "r1 sends r2 its Join(*,$SUPP_GROUP) unprompted"
	else
		fail "r2 heard no Join(*,$SUPP_GROUP) from r1 in $((SUPP_PERIOD + 15))s, there is nothing to suppress"
		return 1
	fi

	n=$(r1_wc_joins)
	elapsed=0
	while [ "$elapsed" -lt "$SUPP_WINDOW" ]; do
		craft_on r2 "$SUPP_ADDR" hello -H 105
		craft_on r2 "$SUPP_ADDR" join -u "$RP_ADDR" -g "$SUPP_GROUP" -w -r "$RP_ADDR"
		sleep "$SUPP_EVERY"
		elapsed=$((elapsed + SUPP_EVERY))
	done
	if [ "$(r1_wc_joins)" -eq "$n" ]; then
		ok "r1 sent no Join(*,$SUPP_GROUP) in ${SUPP_WINDOW}s of hearing $SUPP_ADDR send one every ${SUPP_EVERY}s"
	else
		fail "r1 sent $(( $(r1_wc_joins) - n )) Join(*,$SUPP_GROUP) while $SUPP_ADDR was sending the same one"
	fi
	if joined_on r2 "${EPU}112b" "$SUPP_GROUP"; then
		ok "r2 still has the link in (*,$SUPP_GROUP), kept by the Joins r1 held back for"
	else
		fail "r2 dropped (*,$SUPP_GROUP) on the link to r1"
	fi

	print "6. But no longer than the HoldTime of the Join it overheard"
	n=$(r1_wc_joins)
	elapsed=0
	while [ "$elapsed" -lt "$SUPP_SHORT_WAIT" ] && ! r1_wc_joins_above "$n"; do
		if [ $((elapsed % SUPP_EVERY)) -eq 0 ]; then
			craft_on r2 "$SUPP_ADDR" hello -H 105
			craft_on r2 "$SUPP_ADDR" join -u "$RP_ADDR" -g "$SUPP_GROUP" -w -r "$RP_ADDR" \
				-H "$SUPP_SHORT_HOLD"
		fi
		sleep 5
		elapsed=$((elapsed + 5))
	done
	if r1_wc_joins_above "$n"; then
		ok "r1 sent its own Join after ${elapsed}s of hearing Joins with a ${SUPP_SHORT_HOLD}s HoldTime"
	else
		fail "r1 stayed quiet ${SUPP_SHORT_WAIT}s behind Joins that hold r2's state ${SUPP_SHORT_HOLD}s"
	fi

	# RFC 7761 sec. 4.5.4 and the t_override row of sec. 4.11, T1 of
	# doc/rfc7761-compliance.md: a router that hears a Prune(*,G) on its
	# upstream interface while it still wants the group overrides it with a
	# Join after rand(0, Effective_Override_Interval), 2.5 seconds, so that
	# the Join reaches the upstream router inside the J/P_Override_Interval
	# it waits before acting on the Prune, 3 seconds on defaults.  pimd
	# drew whole seconds and then waited for the next 5-second tick, so the
	# Join went out anywhere up to 5 seconds on.  That is under 3 seconds
	# often enough to pass one trial by luck, so there are $OVR_TRIALS, each
	# timed from the Prune in R1's log to the Join in R2's: the jails share
	# one clock.
	print "7. A Prune overheard on the upstream link is overridden in time"
	i=0
	while [ "$i" -lt "$OVR_TRIALS" ]; do
		i=$((i + 1))
		m1=$(log_lines r1)
		m2=$(log_lines r2)
		craft_on r2 "$SUPP_ADDR" hello -H 105
		craft_on r2 "$SUPP_ADDR" prune -u "$RP_ADDR" -g "$SUPP_GROUP" -w -r "$RP_ADDR"
		if ! wait_for 10 log_since r2 "$m2" "Received PIM JOIN from $R1_UP_ADDR to group $SUPP_GROUP "; then
			fail "trial $i: r1 sent no Join(*,$SUPP_GROUP) in 10s of hearing $SUPP_ADDR prune it"
			continue
		fi
		t0=$(log_since r1 "$m1" "Received PIM PRUNE from $SUPP_ADDR to group $SUPP_GROUP " | log_msec | tail -1)
		t1=$(log_since r2 "$m2" "Received PIM JOIN from $R1_UP_ADDR to group $SUPP_GROUP " | log_msec | head -1)
		if [ -z "$t0" ]; then
			fail "trial $i: r1 logged no Prune(*,$SUPP_GROUP) from $SUPP_ADDR, nothing to time the Join from"
		elif [ $((t1 - t0)) -le "$OVR_WINDOW" ]; then
			ok "trial $i: r1 overrode the Prune $((t1 - t0))ms after it, inside ${OVR_WINDOW}ms"
		else
			fail "trial $i: r1 overrode the Prune $((t1 - t0))ms after it, r2 waits ${OVR_WINDOW}ms"
		fi
		sleep 1
	done

	# RFC 7761 sec. 4.3.1, T3: the Hello answering a new neighbour waits
	# rand(0, Triggered_Hello_Delay), 5 seconds, so that a LAN does not
	# answer a rebooting router in the same instant.  pimd sent it at once.
	# A Hello with HoldTime 0 makes $SUPP_ADDR new again for each trial.
	# Every delay is bounded by the 5 seconds, and a pimd that answers at
	# once is told apart by all of them being under ${HELLO_PROMPT}ms, which
	# a uniform draw does one time in 10 per trial.  Any other Hello R1 has
	# to send on the link meanwhile, the periodic one or the one a
	# Join/Prune must follow, can only make a delay look shorter.
	print "8. The Hello answering a new neighbour waits a random delay"
	i=0
	late=0
	while [ "$i" -lt "$HELLO_TRIALS" ]; do
		i=$((i + 1))
		craft_on r2 "$SUPP_ADDR" hello -H 0
		if ! wait_for 10 no_neighbor r1 "$SUPP_ADDR"; then
			fail "trial $i: r1 kept $SUPP_ADDR as a neighbour past a Hello with HoldTime 0"
			continue
		fi
		m1=$(log_lines r1)
		craft_on r2 "$SUPP_ADDR" hello -H 105
		if ! wait_for 15 hello_answer r1 "$m1" "$SUPP_ADDR" "${EP}112a"; then
			fail "trial $i: r1 sent no Hello on ${EP}112a in 15s of meeting $SUPP_ADDR"
			continue
		fi
		d=$(hello_answer r1 "$m1" "$SUPP_ADDR" "${EP}112a")
		if [ "$d" -le $((HELLO_DELAY + HELLO_SLACK)) ]; then
			ok "trial $i: r1 answered $SUPP_ADDR ${d}ms after its Hello"
		else
			fail "trial $i: r1 answered $SUPP_ADDR ${d}ms after its Hello, past Triggered_Hello_Delay"
		fi
		[ "$d" -gt "$HELLO_PROMPT" ] && late=$((late + 1))
	done
	if [ "$late" -gt 0 ]; then
		ok "$late of $HELLO_TRIALS answers came later than ${HELLO_PROMPT}ms, the delay is drawn"
	else
		fail "every answer came within ${HELLO_PROMPT}ms of the Hello, r1 answers new neighbours at once"
	fi

	box_addr_del r2 "${EPU}112b" "$SUPP_ADDR" 2>/dev/null

	# RFC 7761 sec. 4.5.1, the upstream end of step 7: a Prune(*,G) on a
	# link with more than one PIM neighbour holds the interface in
	# Prune-Pending for J/P_Override_Interval, 3 seconds on defaults, so that
	# another router on the link can override it, and then the interface
	# goes and the LAN gets a PruneEcho.  pimd aged that timer on its
	# 5-second tick, armed one tick longer so it could not run out short of
	# the interval, which made it 5 to 10 seconds.  R1 is the upstream here,
	# for $SRC_ADDR and $CRAFT_ADDR on the ED1 LAN: the second is made a
	# neighbour for the step only, and nobody overrides.  Timed from the
	# Prune to the PruneEcho, both in R1's log.
	print "9. A Prune nobody overrides holds the interface for the override interval"
	craft "$SRC_ADDR" hello -H 105
	craft "$CRAFT_ADDR" hello -H 105
	if ! wait_for 30 has_neighbor r1 "$CRAFT_ADDR"; then
		fail "r1 never took $CRAFT_ADDR as a second neighbour on the LAN, there is no Prune-Pending"
	else
		i=0
		while [ "$i" -lt "$PP_TRIALS" ]; do
			i=$((i + 1))
			m1=$(log_lines r1)
			craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$PP_GROUP" -w -r "$RP_ADDR"
			if ! wait_for 10 log_since r1 "$m1" "Received PIM JOIN from $SRC_ADDR to group $PP_GROUP "; then
				fail "trial $i: r1 logged no Join(*,$PP_GROUP) from $SRC_ADDR"
				continue
			fi
			sleep 1
			m1=$(log_lines r1)
			craft "$SRC_ADDR" prune -u "$R1_LAN_ADDR" -g "$PP_GROUP" -w -r "$RP_ADDR"
			if ! wait_for 15 log_since r1 "$m1" ",$PP_GROUP) on ${EP}101b"; then
				fail "trial $i: r1 sent no PruneEcho for $PP_GROUP in 15s of the Prune"
				continue
			fi
			t0=$(log_since r1 "$m1" "Received PIM PRUNE from $SRC_ADDR to group $PP_GROUP " | log_msec | head -1)
			t1=$(log_since r1 "$m1" ",$PP_GROUP) on ${EP}101b" | log_msec | head -1)
			d=$((t1 - t0))
			if [ "$d" -ge $((PP_WINDOW - PP_EARLY)) ] && [ "$d" -le $((PP_WINDOW + PP_LATE)) ]; then
				ok "trial $i: r1 let the interface go ${d}ms after the Prune, the interval is ${PP_WINDOW}ms"
			else
				fail "trial $i: r1 let the interface go ${d}ms after the Prune, the interval is ${PP_WINDOW}ms"
			fi
		done
	fi
	# M1 of doc/rfc7761-compliance.md, the steps from here to 13: RFC 7761
	# keeps (S,G,rpt) state apart from (S,G) state, and pimd had only the
	# one (S,G) entry for both.  $SRC_ADDR and $CRAFT_ADDR are two
	# downstream routers on R1's LAN, and the point of playing them with
	# pimsend is that neither overrides anything unless told: between two
	# pimds the override Join hides what R1 does with the Prune.
	#
	# Sec. 4.5.3 gives a Prune(S,G,rpt) a state machine of its own, which
	# takes the source off what the interface inherits from joins(*,G)
	# and nothing else.  pimd applied it to the (S,G) machine, so the
	# (S,G) Join another router on the LAN still wanted went with it.
	print "10. A Prune(S,G,rpt) leaves another router's Join(S,G) alone"
	craft "$SRC_ADDR" hello -H 105
	craft "$CRAFT_ADDR" hello -H 105
	if ! wait_for 30 has_neighbor r1 "$CRAFT_ADDR"; then
		fail "r1 never took $CRAFT_ADDR as a second neighbour on the LAN"
		return 1
	fi
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$RPT_SG_GROUP" -s "$CRAFT_FAR_SRC"
	if ! wait_for 15 sg_joined_on r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_SG_GROUP"; then
		fail "r1 built no ($CRAFT_FAR_SRC,$RPT_SG_GROUP) joined on the LAN, nothing below can be asked"
		return 1
	fi
	m1=$(log_lines r1)
	craft "$CRAFT_ADDR" prune -u "$R1_LAN_ADDR" -g "$RPT_SG_GROUP" -s "$CRAFT_FAR_SRC" -R
	if ! wait_for 10 has_rpt_msg r1 "$m1" PRUNE "$CRAFT_ADDR" "$RPT_SG_GROUP" "$CRAFT_FAR_SRC"; then
		fail "r1 logged no Prune(S,G,rpt) from $CRAFT_ADDR"
		return 1
	fi
	sleep "$RPT_SETTLE"
	if sg_joined_on r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_SG_GROUP"; then
		ok "r1 kept $SRC_ADDR's Join($CRAFT_FAR_SRC,$RPT_SG_GROUP) past $CRAFT_ADDR's Prune(S,G,rpt)"
	else
		xfail "r1 dropped $SRC_ADDR's Join(S,G) for $CRAFT_ADDR's Prune(S,G,rpt), which sec. 4.5.3 applies to the (S,G,rpt) machine alone"
	fi
	# The control: the same Prune without the RPT bit is one for the
	# (S,G) machine, and nobody overrides it
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$RPT_SG_GROUP" -s "$CRAFT_FAR_SRC"
	if ! wait_for 15 sg_joined_on r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_SG_GROUP"; then
		fail "r1 did not take $SRC_ADDR's Join(S,G) back, there is no control"
	else
		craft "$CRAFT_ADDR" prune -u "$R1_LAN_ADDR" -g "$RPT_SG_GROUP" -s "$CRAFT_FAR_SRC"
		if wait_for 15 sg_not_joined_on r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_SG_GROUP"; then
			ok "the same Prune without the RPT bit does take the Join(S,G) away"
		else
			fail "r1 kept the Join(S,G) past a Prune(S,G) nobody overrode, the Prunes are not being read"
		fi
	fi

	# Sec. 4.5.3 again, on a group joined from the shared tree: the Prune
	# takes the source off the interface once the Prune-Pending Timer runs
	# out, and until then "functions exactly like the NoInfo state".  A
	# Join(S,G,rpt) is how another router on the LAN says it still wants
	# the source, before the timer runs out or after, and pimd had no
	# branch for one at all.  Sec. 4.5.7 is R1's side of it towards R2:
	# with the LAN pruned its inherited_olist(S,G,rpt) is empty and it
	# prunes the source upstream, and when the Join(S,G,rpt) makes it
	# non-empty again it sends R2 one of its own, rather than leave R2
	# to wait for a Join(*,G) that carries no Prune.
	print "11. A Prune(S,G,rpt) takes one source off the shared tree, a Join(S,G,rpt) puts it back"
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -w -r "$RP_ADDR"
	if ! wait_for 15 joined_on r1 "${EP}101b" "$RPT_GROUP"; then
		fail "r1 built no (*,$RPT_GROUP) joined on the LAN, nothing below can be asked"
		return 1
	fi
	m1=$(log_lines r1)
	m2=$(log_lines r2)
	t0=$(date +%s)
	craft "$CRAFT_ADDR" prune -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -s "$CRAFT_FAR_SRC" -R
	if ! wait_for 10 has_rpt_msg r1 "$m1" PRUNE "$CRAFT_ADDR" "$RPT_GROUP" "$CRAFT_FAR_SRC"; then
		fail "r1 logged no Prune(S,G,rpt) from $CRAFT_ADDR"
		return 1
	fi
	pending=yes
	sg_pruned_off r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_GROUP" && pending=no
	if [ $(($(date +%s) - t0)) -ge "$RPT_PROMPT" ]; then
		dprint "the Prune-Pending check came $(($(date +%s) - t0))s late, skipping it"
	elif [ "$pending" = yes ]; then
		ok "r1 still forwards $CRAFT_FAR_SRC on the LAN while the Prune may be overridden"
	else
		xfail "r1 pruned $CRAFT_FAR_SRC off the LAN on receipt, with no Prune-Pending interval for anybody to override it in"
	fi
	if wait_for "$RPT_SETTLE" sg_pruned_off r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_GROUP"; then
		ok "r1 took $CRAFT_FAR_SRC off the LAN and left the rest of $RPT_GROUP on it"
	else
		fail "r1 still forwards $CRAFT_FAR_SRC on the LAN, nobody overrode the Prune(S,G,rpt)"
	fi
	if ! joined_on r1 "${EP}101b" "$RPT_GROUP"; then
		fail "r1 dropped the (*,$RPT_GROUP) Join along with the one source"
	fi
	if wait_for 10 has_rpt_msg r2 "$m2" PRUNE "$R1_UP_ADDR" "$RPT_GROUP" "$CRAFT_FAR_SRC"; then
		ok "r1, with nowhere left to send $CRAFT_FAR_SRC, pruned it off the shared tree at r2"
	else
		fail "r2 heard no Prune(S,G,rpt) from r1 for $CRAFT_FAR_SRC"
	fi

	m2=$(log_lines r2)
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -s "$CRAFT_FAR_SRC" -R
	if wait_for 5 sg_not_pruned_off r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_GROUP"; then
		ok "a Join(S,G,rpt) from $SRC_ADDR put $CRAFT_FAR_SRC back on the LAN"
	else
		xfail "r1 ignored $SRC_ADDR's Join(S,G,rpt), $CRAFT_FAR_SRC stays pruned until the Prune expires"
	fi
	if wait_for 10 has_rpt_msg r2 "$m2" JOIN "$R1_UP_ADDR" "$RPT_GROUP" "$CRAFT_FAR_SRC"; then
		ok "and r1 sent r2 a Join(S,G,rpt) of its own, sec. 4.5.7"
	else
		xfail "r1 sent r2 no Join(S,G,rpt) once it wanted $CRAFT_FAR_SRC again, sec. 4.5.7"
	fi

	# The override proper: the Join(S,G,rpt) arrives inside the interval
	m1=$(log_lines r1)
	craft "$CRAFT_ADDR" prune -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -s "$CRAFT_FAR_SRC" -R
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -s "$CRAFT_FAR_SRC" -R
	if ! wait_for 10 has_rpt_msg r1 "$m1" JOIN "$SRC_ADDR" "$RPT_GROUP" "$CRAFT_FAR_SRC"; then
		fail "r1 logged no Join(S,G,rpt) from $SRC_ADDR"
	else
		sleep "$RPT_SETTLE"
		if sg_not_pruned_off r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_GROUP"; then
			ok "a Join(S,G,rpt) inside the override interval kept $CRAFT_FAR_SRC on the LAN"
		else
			xfail "r1 pruned $CRAFT_FAR_SRC off the LAN although $SRC_ADDR overrode the Prune in time"
		fi
	fi

	# Sec. 4.5.3's two transient states, which is how a Join(*,G) and the
	# Prune(S,G,rpt)s in the same group set are read: the Join moves every
	# pruned source to PruneTmp, the Prunes that follow it put theirs back,
	# and the ones left at the end of the message go.  So the periodic
	# compound message of sec. 4.5.6 holds a prune, and a Join(*,G) that
	# no longer carries one lifts it.  pimd lifted every one on the Join
	# and set the Prune again on the Prune, which kept it only because an
	# entry that had never been joined on the LAN let it skip the
	# Prune-Pending Timer: this step is a guard on the transient states
	# that replaced that, not a deviation reproduced.
	print "12. A Join(*,G) lifts an (S,G,rpt) Prune unless it carries it"
	craft "$CRAFT_ADDR" prune -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -s "$CRAFT_FAR_SRC" -R
	if ! wait_for $((RPT_SETTLE * 2)) sg_pruned_off r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_GROUP"; then
		fail "r1 never took $CRAFT_FAR_SRC off the LAN, nothing below can be asked"
	else
		craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -w -r "$RP_ADDR" -X "$CRAFT_FAR_SRC"
		sleep 1
		if sg_pruned_off r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_GROUP"; then
			ok "a Join(*,G) carrying the Prune(S,G,rpt) kept $CRAFT_FAR_SRC off the LAN"
		else
			fail "a Join(*,G) carrying the Prune(S,G,rpt) put $CRAFT_FAR_SRC back on the LAN"
		fi
		craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -w -r "$RP_ADDR"
		if wait_for 5 sg_not_pruned_off r1 "${EP}101b" "$CRAFT_FAR_SRC" "$RPT_GROUP"; then
			ok "a Join(*,G) without it put $CRAFT_FAR_SRC back"
		else
			fail "r1 kept $CRAFT_FAR_SRC pruned past a Join(*,G) that no longer prunes it"
		fi
	fi

	# Sec. 4.5.7 from the other side of R1: $SUPP_ADDR is a router on R1's
	# link to R2 again, played from R2's jail as in step 5, and it prunes
	# $CRAFT_FAR_SRC off the shared tree at R2.  R1 still wants the source
	# for its LAN, so it is in NotPruned and has to override with a
	# Join(S,G,rpt) inside the J/P_Override_Interval R2 waits.  pimd read
	# the Prune as an (S,G) one, found no (S,G) entry and did nothing.
	# Timed as step 7 is, over $RPT_OVR_TRIALS trials.
	print "13. A Prune(S,G,rpt) overheard upstream is overridden in time"
	box_addr_add r2 "${EPU}112b" "$SUPP_ADDR/24" 2>/dev/null || \
		die "failed adding $SUPP_ADDR to ${EPU}112b on r2"
	craft_on r2 "$SUPP_ADDR" hello -H 105
	if ! wait_for 30 has_neighbor r1 "$SUPP_ADDR"; then
		fail "r1 never took $SUPP_ADDR as a neighbour on its link to r2"
	else
		i=0
		while [ "$i" -lt "$RPT_OVR_TRIALS" ]; do
			i=$((i + 1))
			m1=$(log_lines r1)
			m2=$(log_lines r2)
			craft_on r2 "$SUPP_ADDR" prune -u "$RP_ADDR" -g "$RPT_GROUP" -s "$CRAFT_FAR_SRC" -R
			if ! wait_for 10 has_rpt_msg r2 "$m2" JOIN "$R1_UP_ADDR" "$RPT_GROUP" "$CRAFT_FAR_SRC"; then
				xfail "trial $i: r1 sent no Join(S,G,rpt) in 10s of hearing $SUPP_ADDR prune $CRAFT_FAR_SRC off the shared tree"
				continue
			fi
			t0=$(rpt_msg r1 "$m1" PRUNE "$SUPP_ADDR" "$RPT_GROUP" "$CRAFT_FAR_SRC" | log_msec | tail -1)
			t1=$(rpt_msg r2 "$m2" JOIN "$R1_UP_ADDR" "$RPT_GROUP" "$CRAFT_FAR_SRC" | log_msec | head -1)
			if [ -z "$t0" ]; then
				fail "trial $i: r1 logged no Prune(S,G,rpt) from $SUPP_ADDR, nothing to time the Join from"
			elif [ $((t1 - t0)) -le "$OVR_WINDOW" ]; then
				ok "trial $i: r1 overrode the Prune(S,G,rpt) $((t1 - t0))ms after it, inside ${OVR_WINDOW}ms"
			else
				fail "trial $i: r1 overrode the Prune(S,G,rpt) $((t1 - t0))ms after it, r2 waits ${OVR_WINDOW}ms"
			fi
			sleep 1
		done
	fi

	# rpt-prune-limit: every Prune(S,G,rpt) naming a source R1 holds no
	# entry for makes one, lasting the HoldTime the neighbour chose, so the
	# number is capped.  Past the cap a Prune addressed to R1 is not applied,
	# and one overheard upstream is still overridden, by bringing the (*,G)
	# Join forward: a Join(*,G) that does not carry the Prune is an override
	# too, "End of Message" in R2's sec. 4.5.3 machine.  The control is the
	# sources that did fit, held and pruned off the LAN.
	print "13b. rpt-prune-limit caps the state neighbours' Prune(S,G,rpt) make"
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -w -r "$RP_ADDR"
	used=$(rpt_entries r1)
	if ! wait_for 15 joined_on r1 "${EP}101b" "$RPT_GROUP"; then
		fail "r1 lost the (*,$RPT_GROUP) Join on the LAN, nothing below can be asked"
	elif [ -z "$used" ] || [ "$used" -ge "$RPT_LIMIT" ]; then
		fail "r1 reports '${used}' RPT Prune entries before the step, of a limit of $RPT_LIMIT"
	else
		m1=$(log_lines r1)
		# Topped up rather than filled once: an entry an earlier step
		# left can age out while this one fills, and leave room for the
		# source that is meant to be refused
		i=0
		tries=0
		while [ "$used" -lt "$RPT_LIMIT" ] && [ "$tries" -lt 3 ]; do
			tries=$((tries + 1))
			fill=""
			n=$((RPT_LIMIT - used))
			while [ "$n" -gt 0 ]; do
				fill="$fill -s $RPT_LIMIT_NET.$((100 + i))"
				i=$((i + 1))
				n=$((n - 1))
			done
			# shellcheck disable=SC2086
			craft "$CRAFT_ADDR" prune -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -R -H "$RPT_LIMIT_HOLD" $fill
			wait_for 10 has_sg r1 "$RPT_LIMIT_NET.$((99 + i))" "$RPT_GROUP"
			used=$(rpt_entries r1)
		done
		over="$RPT_LIMIT_NET.$((100 + i))"
		if [ "$used" = "$RPT_LIMIT" ] && \
		   wait_for "$RPT_SETTLE" sg_pruned_off r1 "${EP}101b" "$RPT_LIMIT_NET.$((99 + i))" "$RPT_GROUP"; then
			ok "r1 holds and applies Prune(S,G,rpt) state up to rpt-prune-limit $RPT_LIMIT"
		else
			fail "r1 holds ${used} RPT Prune entries after $i sources were pruned, of a limit of $RPT_LIMIT"
		fi
		craft "$CRAFT_ADDR" prune -u "$R1_LAN_ADDR" -g "$RPT_GROUP" -R -H "$RPT_LIMIT_HOLD" -s "$over"
		if wait_for 10 log_since r1 "$m1" "Not holding ($over,$RPT_GROUP,rpt) for $CRAFT_ADDR"; then
			if has_sg r1 "$over" "$RPT_GROUP"; then
				fail "r1 logged refusing ($over,$RPT_GROUP,rpt) and holds an entry for it anyway"
			else
				ok "r1 refused a Prune(S,G,rpt) past rpt-prune-limit $RPT_LIMIT and made no entry"
			fi
		else
			fail "r1 did not refuse ($over,$RPT_GROUP,rpt) with $RPT_LIMIT entries held"
		fi
		if logged r1 "rpt-prune-limit $RPT_LIMIT reached"; then
			ok "r1 warned that rpt-prune-limit was reached"
		else
			fail "r1 reached rpt-prune-limit without the warning"
		fi

		if ! has_neighbor r1 "$SUPP_ADDR"; then
			fail "r1 lost $SUPP_ADDR as a neighbour, the overheard half cannot be asked"
		else
			i=0
			while [ "$i" -lt "$RPT_OVR_TRIALS" ]; do
				i=$((i + 1))
				m1=$(log_lines r1)
				m2=$(log_lines r2)
				craft_on r2 "$SUPP_ADDR" prune -u "$RP_ADDR" -g "$RPT_GROUP" -s "$over" -R
				if ! wait_for 10 log_since r1 "$m1" "Not holding ($over,$RPT_GROUP,rpt) for $SUPP_ADDR"; then
					fail "trial $i: r1 did not refuse the overheard ($over,$RPT_GROUP,rpt) at the limit"
					continue
				fi
				if ! wait_for 10 has_wc_join r2 "$m2" "$R1_UP_ADDR" "$RPT_GROUP" "$RP_ADDR"; then
					fail "trial $i: r1 sent no Join(*,$RPT_GROUP) in 10s of hearing $SUPP_ADDR prune $over"
					continue
				fi
				t0=$(rpt_msg r1 "$m1" PRUNE "$SUPP_ADDR" "$RPT_GROUP" "$over" | log_msec | tail -1)
				t1=$(wc_join r2 "$m2" "$R1_UP_ADDR" "$RPT_GROUP" "$RP_ADDR" | log_msec | head -1)
				if [ -z "$t0" ]; then
					fail "trial $i: r1 logged no Prune(S,G,rpt) from $SUPP_ADDR, nothing to time the Join from"
				elif [ $((t1 - t0)) -le "$OVR_WINDOW" ]; then
					ok "trial $i: at the limit r1 overrode with a Join(*,G) $((t1 - t0))ms after the Prune, inside ${OVR_WINDOW}ms"
				else
					fail "trial $i: at the limit r1's Join(*,G) came $((t1 - t0))ms after the Prune, r2 waits ${OVR_WINDOW}ms"
				fi
				sleep 1
			done
		fi
	fi
	box_addr_del r2 "${EPU}112b" "$SUPP_ADDR" 2>/dev/null

	# Step 16 needs $CRAFT_ADDR to be nobody's neighbour again
	craft "$CRAFT_ADDR" hello -H 0
	if ! wait_for 10 no_neighbor r1 "$CRAFT_ADDR"; then
		fail "r1 kept $CRAFT_ADDR as a neighbour past a Hello with HoldTime 0"
		return 1
	fi

	# RFC 7761 sec. 4.7.1, R2 of doc/rfc7761-compliance.md: a group range
	# learned after a group already has state takes that group over when
	# it is the longer match, rather than leaving it on the RP it had.  The
	# (S,G) above is on 224.0.0.0/4 and R2's RP; a second one, outside the
	# new range, is the control that the range and not the whole RP set
	# moved.  It sits here because it needs a converged domain with groups
	# on it, which step 15 takes away; the short holdtime is so the range is
	# gone again well inside that step's wait.
	print "14. A longer group range takes over the groups inside it"
	# Step 1's Hello has run out by now, and a Join from an address with
	# no Hello is refused before it builds anything
	craft "$SRC_ADDR" hello -H 105
	if ! wait_for 30 has_neighbor r1 "$SRC_ADDR"; then
		fail "r1 did not take $SRC_ADDR back as a neighbour"
		return 1
	fi
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$CRAFT_OUT_GROUP" -s "$CRAFT_FAR_SRC" -H 65535
	if ! wait_for 15 route_held r1 "$CRAFT_FAR_SRC" "$CRAFT_OUT_GROUP"; then
		fail "r1 built no ($CRAFT_FAR_SRC,$CRAFT_OUT_GROUP), there is no control"
	elif [ "$(route_rp r1 "$CRAFT_FAR_SRC" "$GROUP")" != "$RP_ADDR" ]; then
		fail "($CRAFT_FAR_SRC,$GROUP) maps to $(route_rp r1 "$CRAFT_FAR_SRC" "$GROUP") before any longer range exists"
	else
		craft "$SRC_ADDR" hello -H 105
		craft "$SRC_ADDR" bootstrap -u "$SRC_ADDR" -g "$CRAFT_RANGE" -m "$CRAFT_RANGE_LEN" \
		      -r "$SRC_ADDR" -p "$CRAFT_PRIO" -H 30
		if ! wait_for 15 has_rp r1 "$CRAFT_RANGE"; then
			fail "r1 never installed $CRAFT_RANGE/$CRAFT_RANGE_LEN, so where its groups map says nothing"
		elif wait_for 10 route_rp_is r1 "$CRAFT_FAR_SRC" "$GROUP" "$SRC_ADDR"; then
			ok "($CRAFT_FAR_SRC,$GROUP) moved to $SRC_ADDR, the RP of $CRAFT_RANGE/$CRAFT_RANGE_LEN"
		else
			fail "($CRAFT_FAR_SRC,$GROUP) stayed on $(route_rp r1 "$CRAFT_FAR_SRC" "$GROUP"), the longest match is $CRAFT_RANGE/$CRAFT_RANGE_LEN"
		fi
		if [ "$(route_rp r1 "$CRAFT_FAR_SRC" "$CRAFT_OUT_GROUP")" = "$RP_ADDR" ]; then
			ok "($CRAFT_FAR_SRC,$CRAFT_OUT_GROUP), outside the range, stayed on $RP_ADDR"
		else
			fail "($CRAFT_FAR_SRC,$CRAFT_OUT_GROUP) moved to $(route_rp r1 "$CRAFT_FAR_SRC" "$CRAFT_OUT_GROUP"), and it is not in $CRAFT_RANGE/$CRAFT_RANGE_LEN"
		fi
	fi

	# The unicast branch is reachable only while this router knows no
	# dynamic RP -- it is there for RFC 5059 sec. 3.5.2, a DR handing the
	# RP set to a router that has just come up -- so R2 has to stop being
	# the BSR and R1's RP set has to age out before any of it can be
	# asked.  That is the state a booting router is in, which is the
	# state the entry is about.
	print "15. R1 is put back where a booting router starts, with no RP"
	dprint "stopping the BSR and waiting for R1's dynamic RP to expire ..."
	[ -f "$WORKDIR/r2.pid" ] && ${SUDO} pkill -9 -F "$WORKDIR/r2.pid" 2>/dev/null
	if wait_for "$CRAFT_RP_WAIT" no_dynamic_rp r1; then
		ok "r1 holds no dynamic RP, the unicast branch is reachable"
	else
		fail "r1 still holds $(pimctl r1 show rp 2>/dev/null | awk '$4 != "Forever" && NF { print $2 }' | tr '\n' ' ')after ${CRAFT_RP_WAIT}s"
		return 1
	fi

	print "16. A unicast Bootstrap from a stranger on the LAN is refused"
	craft "$CRAFT_ADDR" bootstrap -d "$R1_LAN_ADDR" -u "$CRAFT_ADDR" \
	      -g 224.0.0.0 -m 4 -r "$CRAFT_ADDR" -p "$CRAFT_PRIO"
	if wait_for 10 logged r1 "Ignoring unicast Bootstrap from $CRAFT_ADDR"; then
		ok "r1 refused the RP set of a router it has had no Hello from"
	else
		fail "r1 took the RP set from $CRAFT_ADDR, which never said Hello"
	fi
	if has_rp r1 "$CRAFT_ADDR"; then
		fail "r1 installed $CRAFT_ADDR as RP anyway"
	else
		ok "r1's RP set is untouched"
	fi

	# The other half, and the reason the check is safe: the DR that
	# unicasts an RP set has sent its Hello first, on the same path,
	# immediately before.  Here that Hello is sent explicitly.
	print "17. The same Bootstrap, once its sender has said Hello, is taken"
	craft "$CRAFT_ADDR" hello -H 105
	if wait_for 30 has_neighbor r1 "$CRAFT_ADDR"; then
		ok "r1 took $CRAFT_ADDR as a neighbour"
	else
		fail "r1 never saw the Hello from $CRAFT_ADDR"
		return 1
	fi
	craft "$CRAFT_ADDR" bootstrap -d "$R1_LAN_ADDR" -u "$CRAFT_ADDR" \
	      -g 224.0.0.0 -m 4 -r "$CRAFT_ADDR" -p "$CRAFT_PRIO"
	if wait_for 15 has_rp r1 "$CRAFT_ADDR"; then
		ok "r1 learned RP $CRAFT_ADDR from the unicast Bootstrap"
	else
		fail "r1 refused it even from a neighbour, RFC 5059 sec. 3.5.2 cannot work"
		return 1
	fi

	# Now that R1 holds an RP from a sender it trusts, a malformed
	# Bootstrap from that same sender must cost it nothing.  Rejecting
	# one after the BSR address, the fragment tag and the segmented RP
	# list have been committed -- which is where the group ranges are
	# read -- would hand any neighbour the domain's RP set for the price
	# of one bad byte.
	print "18. A malformed Bootstrap from that neighbour changes nothing"
	craft "$CRAFT_ADDR" bootstrap -u "$CRAFT_ADDR" -g 224.0.0.0 \
	      -m "$CRAFT_BADLEN" -r "$CRAFT_ADDR" -p "$CRAFT_PRIO"
	if wait_for 10 logged r1 "Ignoring Bootstrap from $CRAFT_ADDR, group mask length"; then
		ok "r1 refused a group range wider than an address"
	else
		fail "r1 installed a group range whose mask length is $CRAFT_BADLEN"
	fi
	craft "$CRAFT_ADDR" bootstrap -u "$CRAFT_ADDR" -g 224.0.0.0 -m 4 \
	      -M "$CRAFT_BADLEN" -r "$CRAFT_ADDR" -p "$CRAFT_PRIO"
	if wait_for 10 logged r1 "hash mask length $CRAFT_BADLEN is wider than an address"; then
		ok "r1 refused a hash mask length wider than an address"
	else
		fail "r1 accepted a hash mask length of $CRAFT_BADLEN"
	fi
	if has_rp r1 "$CRAFT_ADDR"; then
		ok "r1 still holds the RP it had, both were refused before anything moved"
	else
		fail "r1 lost its RP set to a malformed Bootstrap"
	fi

	# And a well-formed one for the SSM range, which is the way in S1 of
	# doc/rfc7761-compliance.md describes.  config.c synthesizes a static
	# RP at $SSM_VIRTUAL_RP for every SSM range in effect, and it lands
	# on a grp_mask_t of its own: a Bootstrap naming that same prefix
	# used to stamp the mask with its fragment tag and have the collector
	# delete the synthesized entry, after which the group ran on the
	# 90-second RP the second copy in find_route() adds and went down
	# with it.  Static entries are marked now, so what arrives is kept
	# beside what was configured.
	craft "$CRAFT_ADDR" bootstrap -u "$CRAFT_ADDR" -g 232.0.0.0 -m 8 \
	      -r "$CRAFT_ADDR" -p "$CRAFT_PRIO"
	sleep 2
	if has_static_rp r1 "$SSM_VIRTUAL_RP"; then
		ok "r1 kept the RP it invents for the SSM range"
	else
		fail "a Bootstrap for the SSM range deleted it, and the group now runs on a 90s RP"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# The packet format section of doc/rfc7761-compliance.md, which is
	# every entry that wanted a message pimd will not build.  R1 is the
	# RP here as well as the DR's router, so the Register assertions have
	# somewhere to go.
	print "19. A message whose version is not 2 is discarded"
	craft "$SRC_ADDR" hello -V 3 -H 105
	if wait_for 10 logged r1 "Ignoring PIM v3"; then
		ok "r1 refused a PIM v3 Hello"
	else
		fail "r1 parsed a v3 message as though it were v2, sec. 4.9 says discard"
	fi

	print "20. And one sent to a destination its type may not use"
	craft "$SRC_ADDR" hello -d "$R1_LAN_ADDR" -H 105
	if wait_for 10 logged r1 "not a destination that message may use"; then
		ok "r1 refused a Hello unicast to it rather than to ALL-PIM-ROUTERS"
	else
		fail "r1 acted on a unicast Hello, sec. 4.9's table has that one multicast"
	fi

	# Three encoded addresses in one Join/Prune and three separate checks,
	# so the family is moved on each in turn: -f moves every one of them,
	# which the upstream address is read first of, and -F and -E move the
	# group and source records alone and leave it IPv4.  A parser that
	# checked the upstream address and nothing else would pass the first
	# of these and fail the rest.
	print "21. An encoded address of a family this router cannot read"
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$GROUP" -s "$CRAFT_SRC" -f 2
	if wait_for 10 logged r1 "upstream address family 2 type 0 is not IPv4"; then
		ok "r1 refused a Join whose upstream address declares family 2"
	else
		fail "r1 read an address of another family at IPv4 offsets, sec. 4.9.1"
	fi
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$GROUP" -s "$CRAFT_SRC" -F 2
	if wait_for 10 logged r1 "group address family 2 type 0 is not IPv4"; then
		ok "r1 refused a Join whose group record declares family 2"
	else
		fail "r1 checked the upstream address and read the group record regardless"
	fi
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$GROUP" -s "$CRAFT_SRC" -E 1
	if wait_for 10 logged r1 "group address family 1 type 1 is not IPv4"; then
		ok "r1 refused a Join whose group record declares encoding type 1"
	else
		fail "r1 ignored the encoding type, sec. 4.9.1"
	fi

	print "22. A group range this router does not implement"
	craft "$CRAFT_ADDR" bootstrap -u "$CRAFT_ADDR" -g 224.0.0.0 -m 4 \
	      -r "$CRAFT_ADDR" -p "$CRAFT_PRIO" -B
	if wait_for 10 logged r1 "a range this router does not implement"; then
		ok "r1 refused a range advertised as Bidirectional-PIM"
	else
		fail "r1 installed a Bidir range as an ordinary PIM-SM one, RFC 5059 sec. 3.6"
	fi
	craft "$CRAFT_ADDR" bootstrap -u "$CRAFT_ADDR" -g 224.0.0.0 -m 4 \
	      -r "$CRAFT_ADDR" -p "$CRAFT_PRIO" -Z
	if wait_for 10 logged r1 "a range this router does not implement"; then
		ok "r1 refused a range declaring an administrative scope zone"
	else
		fail "r1 treated a scoped range as global, and it has no scope zones"
	fi

	# sec. 4.9.3 gives the receiver of a Null-Register one rule and all
	# three of its cases are here: a wrong checksum is discarded, a zero
	# one MUST NOT be checked, and a correct one is the control that says
	# the first two were refused for their checksum and not for being
	# Null-Registers.
	# RFC 7761 sec. 4.8.1's rules for a source-specific group, both of
	# them about messages pimd will not send and neither implementation in
	# test/freebsd-interop.sh will either: rule 4, no (*,G) state for a
	# group in the range, and the second half of sec. 4.8.1's Register
	# rule, which is the only thing that quiets an SSM-unaware DR down.
	print "23. No shared tree is built for a group in the SSM range"
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$SSM_GROUP" -w -r "$SSM_VIRTUAL_RP"
	if wait_for 10 logged r1 "shared tree Join for SSM group $SSM_GROUP"; then
		ok "r1 refused a (*,$SSM_GROUP) Join naming $SSM_VIRTUAL_RP"
	else
		fail "r1 acted on a (*,G) Join for an SSM group, sec. 4.8.1 rule 4"
	fi
	if has_mrt r1 "$SSM_GROUP"; then
		fail "r1 holds $(pimctl r1 show mrt 2>/dev/null | awk -v g="$SSM_GROUP" '$2 == g { print $1 }' | tr '\n' ' ')for $SSM_GROUP, which calc_oifs() would merge into every (S,G)"
	else
		ok "r1 built no state for $SSM_GROUP at all"
	fi

	print "24. And a Register for one is answered, not merely dropped"
	craft "$SRC_ADDR" register -d "$R1_LAN_ADDR" -g "$SSM_GROUP" -s "$CRAFT_FAR_SRC"
	if wait_for 10 logged r1 "REGISTER STOP.*group = $SSM_GROUP"; then
		ok "r1 answered an SSM Register with a Register-Stop"
	else
		fail "r1 dropped it silently, so an SSM-unaware DR keeps encapsulating at the data rate"
	fi

	print "25. A Null-Register is believed only where its checksum allows"
	craft "$SRC_ADDR" register -d "$R1_LAN_ADDR" -N -K -g "$GROUP" -s "$CRAFT_SRC"
	if wait_for 10 logged r1 "bad checksum in the dummy IP header"; then
		ok "r1 discarded a Null-Register whose dummy header checksum is wrong"
	else
		fail "r1 took the source and group out of a dummy header it never checked"
	fi
	${SUDO} : > "$WORKDIR/r1.log.mark" 2>/dev/null || true
	craft "$SRC_ADDR" register -d "$R1_LAN_ADDR" -N -0 -g "$GROUP" -s "$CRAFT_SRC"
	craft "$SRC_ADDR" register -d "$R1_LAN_ADDR" -N -g "$GROUP" -s "$CRAFT_SRC"
	if [ "$(${SUDO} grep -c 'bad checksum in the dummy IP header' "$WORKDIR/r1.log")" -eq 1 ]; then
		ok "a zero checksum and a correct one were both let through"
	else
		fail "r1 refused a Null-Register whose checksum it must not check, or one that was correct"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# RFC 5059 sec. 3.5.1's No-Forward bit, whose whole point is that the
	# receiver skips the RPF check.  $NOFWD_BSR is an address nothing in
	# the lab has a route to, so the check cannot pass: without the bit
	# the message is dropped for want of an RPF neighbour toward the BSR,
	# with it the message is the refresh a router that has just come up
	# is meant to take.  The same message twice is what makes it the bit
	# and not the message.
	# RFC 7761 sec. 6.2's other option, the one A1 was about: which
	# routers this interface accepts PIM from.  R1 has run the whole
	# scenario with one configured -- every assertion above passed with
	# it on -- and $DENIED_ADDR is the address on the same subnet that it
	# does not name.  Being on a subnet R1 has a VIF on is all that used
	# to be asked of a router before it could become a neighbour, take
	# the DR role, join the assert election and have its Joins believed.
	print "26. A router the interface does not name is not a neighbour"
	box_addr_add ed1 "${EP}101a" "$DENIED_ADDR/24" 2>/dev/null || \
		die "failed adding $DENIED_ADDR to ${EP}101a on ed1"
	craft "$DENIED_ADDR" hello -H 105
	if wait_for 10 logged r1 "Ignoring PIM HELLO from $DENIED_ADDR"; then
		ok "r1 refused a Hello from $DENIED_ADDR, which its accept-nbr-from does not name"
	else
		fail "r1 took a Hello from an address it was told not to accept"
	fi
	if has_neighbor r1 "$DENIED_ADDR"; then
		fail "r1 has $DENIED_ADDR as a neighbour anyway"
	else
		ok "r1 has no neighbour at $DENIED_ADDR"
	fi
	# The control, and the whole scenario above it: the addresses the
	# same list does name are still neighbours.
	if has_neighbor r1 "$SRC_ADDR" && has_neighbor r1 "$CRAFT_ADDR"; then
		ok "$SRC_ADDR and $CRAFT_ADDR are neighbours still, the list is not refusing everybody"
	else
		fail "r1 lost a neighbour the list names, so the filter refuses more than it was told to"
	fi

	print "27. The No-Forward bit is what waives the RPF check"
	craft "$SRC_ADDR" bootstrap -u "$NOFWD_BSR" -g "$NOFWD_RANGE" -m 16 \
	      -r "$SRC_ADDR" -p "$CRAFT_PRIO"
	sleep 2
	if has_rp r1 "$NOFWD_RANGE"; then
		fail "r1 took a Bootstrap whose BSR it has no route to, without the bit that waives the check"
	else
		ok "r1 dropped it, the RPF check toward $NOFWD_BSR cannot pass"
	fi
	craft "$SRC_ADDR" bootstrap -n -u "$NOFWD_BSR" -g "$NOFWD_RANGE" -m 16 \
	      -r "$SRC_ADDR" -p "$CRAFT_PRIO"
	if wait_for 15 has_rp r1 "$NOFWD_RANGE"; then
		ok "r1 took the same message once it carried the No-Forward bit"
	else
		fail "r1 dropped it even with the bit set, which is the one thing the bit is for"
	fi

	# And the other half of the same section: it is not passed on.  This
	# one names a BSR both routers have a route to and whose RPF
	# neighbour is the sender, so nothing but the bit stops R1 forwarding
	# it and nothing but the bit stops R2 taking what R1 forwarded.
	print "28. And it is not forwarded onward"
	# Step 15 stopped the BSR, and a dead router learns nothing whatever
	# R1 does, so this needs it back: without a live R2 the assertion
	# below passes for the wrong reason, which is how the first version
	# of it passed with the fix reverted.
	start_pimd r2
	if ! wait_for 30 pimd_is_up r2; then
		fail "r2 did not come back, so what it learns says nothing"
		return 1
	fi
	# And R1 has to have it as a neighbour again before any of this
	# means anything: the forwarding loop skips a VIF with VIFF_NONBRS
	# on it, which is what R1's link to R2 carries while R2 is gone, so
	# a message sent too early is not forwarded for a reason that has
	# nothing to do with the bit.
	if ! wait_for 90 has_neighbor r1 "$RP_ADDR"; then
		fail "r1 never saw r2 again, and would not forward to it whatever the bit said"
		return 1
	fi
	craft "$SRC_ADDR" bootstrap -n -u "$SRC_ADDR" -g "$NOFWD_RANGE2" -m 16 \
	      -r "$SRC_ADDR" -p "$NOFWD_PRIO"
	if ! wait_for 15 has_rp r1 "$NOFWD_RANGE2"; then
		fail "r1 did not take it at all, so what r2 does says nothing"
		return 1
	fi
	# Asked of R2's log and not of its RP table: whether it installs the
	# range depends on its own BSR state, and what is under test is
	# whether the message reached it at all.  The priority is what tells
	# this message from every other Bootstrap on the wire.
	sleep 5
	if logged r2 "Bootstrap candidate $SRC_ADDR, priority $NOFWD_PRIO"; then
		fail "r2 received it, so r1 passed on a message RFC 5059 sec. 3.4 does not forward"
	else
		ok "r2 never saw it, r1 kept a No-Forward Bootstrap to itself"
	fi

	# RFC 7761 sec. 4.3.4, from an encoder that is not pimd's.  Each Hello
	# replaces the list the last one left, so every step here is also the
	# control for the one after it: the list is seen to be there before
	# it is seen to go.
	print "29. A Hello Address List is kept, replaced and cleared"
	craft "$SRC_ADDR" hello -H 105 -A "$SRC_ADDR" -A "$CRAFT_SECADDR"
	if wait_for 10 has_secaddr r1 "$SRC_ADDR" "$CRAFT_SECADDR"; then
		ok "r1 holds $CRAFT_SECADDR as a secondary address of $SRC_ADDR"
	else
		fail "r1 did not take the Address List of a well-formed Hello"
		return 1
	fi
	if has_secaddr r1 "$SRC_ADDR" "$SRC_ADDR"; then
		fail "r1 lists $SRC_ADDR as a secondary address of itself, sec. 4.3.4 excludes it"
	else
		ok "the sender's primary address, listed too, was left out"
	fi

	# A list of another family is not one the neighbour's IPv4 next hops
	# can be mapped through, and it is not a reason to lose the
	# neighbour either: sec. 4.9.2 has an option never stand in the way
	# of an adjacency.
	craft "$SRC_ADDR" hello -H 105 -A "$CRAFT_SECADDR" -f 2
	sleep 2
	if has_secaddr r1 "$SRC_ADDR" "$CRAFT_SECADDR"; then
		fail "r1 kept $CRAFT_SECADDR after a Hello whose list is not IPv4"
	else
		ok "a list that is not IPv4 left $SRC_ADDR no secondary addresses"
	fi
	if has_neighbor r1 "$SRC_ADDR"; then
		ok "and $SRC_ADDR is still a neighbour"
	else
		fail "r1 dropped $SRC_ADDR over an Address List it could not read"
	fi

	craft "$SRC_ADDR" hello -H 105 -A "$CRAFT_SECADDR"
	if ! wait_for 10 has_secaddr r1 "$SRC_ADDR" "$CRAFT_SECADDR"; then
		fail "r1 did not take the list back, so the step below says nothing"
		return 1
	fi
	craft "$SRC_ADDR" hello -H 105
	sleep 2
	if has_secaddr r1 "$SRC_ADDR" "$CRAFT_SECADDR"; then
		fail "r1 kept $CRAFT_SECADDR after a Hello with no Address List, sec. 4.3.4 says delete"
	else
		ok "a Hello without the option cleared the list"
	fi

	result
}

# The pid of the pimd running in $1, out of the file it wrote
fz_pimd_pid() {
	${SUDO} cat "$WORKDIR/$1.pid" 2>/dev/null | tr -d ' \t\n'
}

# The RP address of router $1's dynamic entry for $FUZZ_RP_RANGE, empty when
# it holds none.  The static entries config.c installs for the SSM range are
# not it: those say Forever and Static.
fz_group_rp() {
	pimctl "$1" show rp 2>/dev/null | \
		awk -v r="$FUZZ_RP_RANGE" '$1 == r && $NF == "Dynamic" { print $2 }'
}

# Has router $1 logged $3 since its first $2 lines?
fz_logged_since() {
	log_since "$1" "$2" "$3" >/dev/null 2>&1
}

# $FUZZ_COUNT mutants of message type $1, drawn from seed $2, sent from ED1
# at R1.  Each type gets the options it needs to be built at all -- a
# Join/Prune with no group is a Join/Prune pimsend refuses to write -- and
# a seed of its own, or every type would flip the same offsets.
#
# -x flips bytes of the body only and the checksum is recomputed after the
# flips, so these arrive as messages R1 will parse rather than as messages
# pim.c drops on the way in; that is the point of the scenario and it is
# asserted below by what R1 logged.
fz_flood() {
	fzf_type=$1
	fzf_seed=$2
	fzf_mutate="-x $FUZZ_FLIPS -S $fzf_seed -c $FUZZ_COUNT"

	case $fzf_type in
	hello)
		craft "$SRC_ADDR" hello -H 105 $fzf_mutate ;;
	join|prune)
		craft "$SRC_ADDR" "$fzf_type" -u "$R1_LAN_ADDR" -g "$GROUP" \
		      -s "$CRAFT_SRC" $fzf_mutate ;;
	assert)
		craft "$SRC_ADDR" assert -g "$GROUP" -s "$CRAFT_SRC" $fzf_mutate ;;
	bootstrap)
		craft "$SRC_ADDR" bootstrap -u "$SRC_ADDR" -g 224.0.0.0 -m 4 \
		      -r "$SRC_ADDR" -p "$CRAFT_PRIO" $fzf_mutate ;;
	candrp)
		craft "$SRC_ADDR" candrp -r "$SRC_ADDR" -g 224.0.0.0 -m 4 $fzf_mutate ;;
	register)
		craft "$SRC_ADDR" register -d "$R1_LAN_ADDR" -g "$GROUP" \
		      -s "$CRAFT_SRC" $fzf_mutate ;;
	regstop)
		craft "$SRC_ADDR" regstop -d "$R1_LAN_ADDR" -g "$GROUP" \
		      -s "$CRAFT_SRC" $fzf_mutate ;;
	*)
		die "fuzz: no option set for message type $fzf_type" ;;
	esac
}

# fuzz: R1 under a flood of PIM messages nobody wrote on purpose.
#
# crafted sends messages that are wrong in one named way each, and asserts
# what the parser does with that field.  This sends messages that are wrong
# in no particular way: pimsend builds one of each type, flips $FUZZ_FLIPS
# bytes of its body, computes the checksum afterwards so the mutant reaches
# a parser instead of dying at the checksum test that opens most of them,
# and sends $FUZZ_COUNT of them -- a fresh draw per packet, and the same
# draw on any machine from the same $FUZZ_SEED.  An input that trips
# something here is an input somebody can send again.
#
# What this reaches that crafted cannot is the combination nobody thought
# of, which is the whole of why fuzzing exists.  What it reaches that the
# in-process harnesses of test/fuzz/ cannot is a *running* daemon: their
# parsers are called with a fabricated vif table and no neighbours, while
# these arrive at a pimd that has a neighbour, an RP set, a kernel MFC and
# a register vif behind it, from an address it accepted a Hello from.  The
# two are not substitutes -- the harness explores in a minute what this
# sends in an hour, and this exercises state the harness has none of.
#
# Under SANITIZE=yes the sanitizers are the assertion: a read past the end
# of a message or an undefined shift is reported where it happens, and
# check_sanitizer() fails the scenario whatever the steps below said.
# Without them a mutant that corrupts memory quietly passes every one of
# them, so run this both ways, and read a green run without sanitizers as
# "pimd stayed up", nothing more.
#
# The liveness steps are not the point, but they are not nothing either: a
# daemon that stops answering, loses its neighbours or forgets the RP set
# after four thousand malformed messages has been denied service by anybody
# on its LAN.  Each of them is asked before the flood as well as after,
# because an assertion that was already false proves nothing when it fails,
# and step 4 is there for the same reason -- a flood the kernel dropped on
# the way in would leave every other step green.
check_fuzz() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. The state the flood has to leave standing"
	craft "$SRC_ADDR" hello -H 105
	if wait_for 30 has_neighbor r1 "$SRC_ADDR"; then
		ok "r1 took $SRC_ADDR as a neighbour, so pimsend reaches it"
	else
		fail "r1 never saw a well-formed Hello, nothing below would mean anything"
		return 1
	fi

	# R2's address on the link it shares with R1, which is also the RP
	if wait_for 60 has_neighbor r1 "$RP_ADDR"; then
		ok "r1 has r2 ($RP_ADDR) as a neighbour"
	else
		fail "r1 and r2 are not neighbours, so losing that below says nothing"
		return 1
	fi

	if wait_for "$FUZZ_RP_WAIT" has_dynamic_rp r1 "$RP_ADDR"; then
		ok "r1 learned $RP_ADDR as the RP from the bootstrap router"
	else
		fail "r1 has no RP from the BSR, so forgetting one below says nothing"
		return 1
	fi

	fz_pid=$(fz_pimd_pid r1)
	if [ -n "$fz_pid" ]; then
		ok "r1: pimd is pid $fz_pid"
	else
		fail "r1: no pid file at $WORKDIR/r1.pid"
		return 1
	fi

	fz_lines=$(log_lines r1)

	print "3. $FUZZ_COUNT mutants of every message type, $FUZZ_FLIPS bytes flipped in each"
	fz_seed=$FUZZ_SEED
	fz_sent=0
	for fz_type in $FUZZ_TYPES; do
		fz_flood "$fz_type" "$fz_seed"
		fz_seed=$((fz_seed + 1))
		fz_sent=$((fz_sent + FUZZ_COUNT))
	done
	ok "$fz_sent mutants sent from $SRC_ADDR, seeds $FUZZ_SEED..$((fz_seed - 1))"

	print "4. They reached pimd, rather than the kernel or the floor"
	fz_seen=$(log_since r1 "$fz_lines" "$SRC_ADDR" | wc -l | tr -d ' ')
	if [ "$fz_seen" -gt 0 ]; then
		ok "r1 logged $fz_seen lines about $SRC_ADDR while the flood ran"
	else
		fail "r1 logged nothing about $SRC_ADDR, the flood never got to it"
		return 1
	fi

	print "5. It is still the same process"
	if wait_for 10 pimd_is_up r1; then
		ok "r1: pimd still answers on its pimctl socket"
	else
		fail "r1: pimd stopped answering, see $WORKDIR/r1.log"
		return 1
	fi

	fz_now=$(fz_pimd_pid r1)
	if [ "$fz_now" = "$fz_pid" ]; then
		ok "r1: pid $fz_pid throughout, so it never died and came back"
	else
		fail "r1: pid was $fz_pid and is now ${fz_now:-gone}"
	fi

	print "6. And it still knows what it knew"
	if has_neighbor r1 "$RP_ADDR"; then
		ok "r1 still has r2 ($RP_ADDR) as a neighbour"
	else
		fail "r1 lost r2 as a neighbour over the flood"
	fi

	if has_neighbor r1 "$SRC_ADDR"; then
		ok "r1 still has $SRC_ADDR as a neighbour"
	else
		fail "r1 dropped $SRC_ADDR, whose Hello was the only well-formed one"
	fi

	# *That* it holds an RP is the assertion; which one it holds cannot be.
	# A mutant Bootstrap that comes out valid is a BSR takeover, and a
	# router that believes it is PIM working as RFC 7761 sec. 4.7
	# specifies: the flood comes from an address that has said Hello, and
	# $CRAFT_PRIO beats the priority R2 advertises, so one draw in five
	# hundred is enough.  The RP address inside that message is data the
	# message carries, and a flip lands in it as readily as anywhere else,
	# so R1 ends up holding an address nothing on the LAN ever claimed --
	# 10.174.1.10, in the run this was written from, which is the sender's
	# address with one octet moved.  That is the parser doing its job on a
	# packet somebody lied in.  accept-nbr-from is the answer to it, and
	# crafted is where that is asserted; this scenario runs without it so
	# the parsers see everything.
	#
	# What would be the bug is holding no RP at all: the RP set gone, not
	# replaced, from messages that are refused one after another.
	fz_rp=$(fz_group_rp r1)
	if [ -z "$fz_rp" ]; then
		fail "r1 holds no dynamic RP for $FUZZ_RP_RANGE at all after the flood"
	elif [ "$fz_rp" = "$RP_ADDR" ]; then
		ok "r1 still holds r2's RP ($RP_ADDR), no mutant Bootstrap was believed"
	else
		ok "r1 holds $fz_rp for $FUZZ_RP_RANGE: a mutant Bootstrap was believed, which is sec. 4.7"
	fi

	print "7. A well-formed Join is still acted on"
	fz_lines=$(log_lines r1)
	craft "$SRC_ADDR" join -u "$R1_LAN_ADDR" -g "$GROUP" -s "$CRAFT_SRC"
	if wait_for 10 fz_logged_since r1 "$fz_lines" \
		     "Received PIM JOIN/PRUNE from $SRC_ADDR"; then
		ok "r1 parsed a well-formed Join after the flood"
	else
		fail "r1 ignored a well-formed Join after the flood, it is deaf"
	fi

	print "8. The routers behind it came through as well"
	for r in r2 r3; do
		if pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done

	result
}

# Send one crafted PIM message from jail $1, sourced at $2
craft_on() {
	jail=$1
	addr=$2
	shift 2
	box_run "$jail" "$PIMSEND" -i "$addr" "$@" || \
		die "failed sending a crafted $1 from $addr on $jail"
}

# Join(*,$SUPP_GROUP) messages R2 has had from R1 so far, and for
# wait_for(), whether that is more than $1
r1_wc_joins() {
	${SUDO} grep -c "Received PIM JOIN from $R1_UP_ADDR to group $SUPP_GROUP for source $RP_ADDR" \
		"$WORKDIR/r2.log" 2>/dev/null || true
}
r1_wc_joins_above() { [ "$(r1_wc_joins)" -gt "$1" ]; }

# Lines in router $1's log so far, and the lines holding $3 written after
# the first $2 of them
# The file is opened by wc and not by a redirection: the shell doing the
# redirecting is not the one sudo made root, and the log is root's.
log_lines() { ${SUDO} wc -l "$WORKDIR/$1.log" | awk '{ print $1 }'; }
log_since() {
	${SUDO} tail -n +$(($2 + 1)) "$WORKDIR/$1.log" 2>/dev/null | grep -F "$3"
}

# Is interface $2 in the Joined, or the Outgoing, map of router $1's ($3,$4)
# entry?  Neither is, of an entry that does not exist.
sg_joined_on()   { map_isset "$1" "$2" "$(route_map "$1" "$3" "$4" Joined)"; }
sg_forwards_on() { map_isset "$1" "$2" "$(route_map "$1" "$3" "$4" Outgoing)"; }
sg_not_joined_on() { ! sg_joined_on "$@"; }

# Has router $1 taken source $3 of group $4 off interface $2?  Only an
# (S,G) entry can say so: without one the (*,G) forwards every source.
sg_pruned_off() { has_sg "$1" "$3" "$4" && ! sg_forwards_on "$@"; }
sg_not_pruned_off() { ! sg_pruned_off "$@"; }

# The (S,G,rpt) $3 (JOIN or PRUNE) from $4 for group $5 and source $6 in
# router $1's log after its first $2 lines, and the time of the first one
rpt_msg() {
	log_since "$1" "$2" "Received PIM $3 from $4 to group $5 for source $6 on " | \
		grep '(S,G,rpt)$'
}
has_rpt_msg() { rpt_msg "$@" >/dev/null; }

# The (S,G) entries router $1 holds for neighbours' Prune(S,G,rpt), from the
# "RPT Prune entries: N of LIMIT" line of pimctl show status
rpt_entries() {
	pimctl "$1" show status 2>/dev/null | \
		awk -F: '/^RPT Prune entries/ { split($2, n, " "); print n[1] }'
}

# The Join(*,G) from $3 for group $4 naming RP $5 in router $1's log after
# its first $2 lines
wc_join() {
	log_since "$1" "$2" "Received PIM JOIN from $3 to group $4 for source $5 on " | \
		grep '(\*,G)$'
}
has_wc_join() { wc_join "$@" >/dev/null; }

# The time of day of each log line read, "r1: HH:MM:SS.mmm ...", in
# milliseconds
log_msec() {
	awk '{ split($2, t, "[:.]"); print ((t[1] * 60 + t[2]) * 60 + t[3]) * 1000 + t[4] }'
}

# Milliseconds from router $1 meeting neighbour $3 to the next Hello it sent
# on interface $4, counting log lines after the first $2.  Nothing, and
# false, until it has sent one.
hello_answer() {
	${SUDO} tail -n +$(($2 + 1)) "$WORKDIR/$1.log" 2>/dev/null | awk -v n="$3" -v i="$4" '
		function msec(s, t) { split(s, t, "[:.]"); return ((t[1] * 60 + t[2]) * 60 + t[3]) * 1000 + t[4] }
		/Received PIM HELLO from new neighbor/ && $NF == n { t0 = msec($2); next }
		t0 != "" && /Sending PIM HELLO on / && $7 == i { print msec($2) - t0; found = 1; exit }
		END { exit !found }
	'
}

no_neighbor() { ! has_neighbor "$@"; }

# Send one crafted PIM message from ED1, sourced at $1
craft() {
	addr=$1
	shift
	box_run ed1 "$PIMSEND" -i "$addr" "$@" || \
		die "failed sending a crafted $1 from $addr"
}

# Has router $1 no RP left but the static ones config.c installs for the
# SSM range?  "show rp" prints Forever in the holdtime column for those.
no_dynamic_rp() {
	! pimctl "$1" show rp 2>/dev/null | grep -q "Dynamic"
}

# Issue #251: R1 is the DR for the directly connected source and the RP
# for the groups it sends to, and nobody ever joins them, so the (S,G)
# entries have an empty outgoing interface list and no kernel MFC entry.
# Their only sign of life is the IGMPMSG_NOCACHE upcall the kernel raises
# every UPCALL_EXPIRE (1.5s on FreeBSD), and process_cache_miss() has to
# restart the entry timer from it.  When it does not, age_routes() deletes
# each entry within one TIMER_INTERVAL of its creation and the table
# content is different every time you look at it.
# ssm: IGMPv3 (S,G) membership state on the last hop router.
#
# The reports are generated by test/igmpv3.c rather than by joining the
# group on ED2.  A kernel join answers every query R3 sends afterwards,
# so the membership can never age out while ED2 is on the LAN, and taking
# ED2 off the LAN destroys the epair and R3's vif with it.  Sending one
# report and stopping is the only way to ask "does this membership expire
# when the receiver goes quiet?", which is assertion 4.
check_ssm() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. A report with two sources creates one membership each"
	ssm_report -t allow "$SSM_SRC1" "$SSM_SRC2"
	if wait_for 15 ssm_count_is 2; then
		ok "R3 holds ($SSM_SRC1,$GROUP) and ($SSM_SRC2,$GROUP)"
	else
		fail "R3 holds $(ssm_sources | tr '\n' ' ')instead of both sources"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "3. Blocking one source leaves the other alone"
	ssm_report -t block "$SSM_SRC2"
	if wait_for 15 ssm_count_is 1 && [ "$(ssm_sources)" = "$SSM_SRC1" ]; then
		ok "R3 dropped $SSM_SRC2 and kept $SSM_SRC1"
	else
		fail "block left $(ssm_sources | tr '\n' ' ')behind"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# The regression.  One timer per group, holding whichever source
	# reported last, means the block above cancelled the only timer the
	# group had: the membership then outlives any timeout, because
	# nothing is left to expire it.  A leave for the last source still
	# cleans up, so only a receiver that goes quiet shows this.
	print "4. The surviving membership ages out once the reports stop"
	dprint "waiting up to $((SSM_TIMEOUT * 2))s, the membership timeout is ${SSM_TIMEOUT}s"
	if wait_for $((SSM_TIMEOUT * 2)) ssm_count_is 0; then
		ok "($SSM_SRC1,$GROUP) expired with no report to refresh it"
	else
		fail "($SSM_SRC1,$GROUP) never expired, no timer left after the block"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "5. A report with more sources than pimd keeps is bounded"
	ssm_report -t allow -n $((SSM_MAX_SOURCES + 144)) -b 10.0.1.100
	sleep 2
	if ! pimctl r3 show status >/dev/null 2>&1; then
		fail "pimd stopped answering after a $((SSM_MAX_SOURCES + 144)) source report"
		return 1
	fi

	num=$(ssm_sources | wc -l | tr -d ' ')
	if [ "$num" -ge 1 ] && [ "$num" -le "$SSM_MAX_SOURCES" ]; then
		ok "R3 kept $num sources, at most $SSM_MAX_SOURCES"
	else
		fail "R3 kept $num sources, the list is not bounded"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# An any-source report for a source-specific group.  RFC 4607 has no
	# meaning for one and RFC 4604 has the IGMPv3 spelling of it ignored,
	# which pimd already did; the v1 and v2 spelling went the other way.
	# accept_group_report() (src/igmp_proto.c) takes the source of an SSM
	# membership as an argument and igmp.c passes the report's IP
	# destination, which for those versions is the group, so the
	# membership was recorded under a multicast "source" and add_leaf()
	# asked for an (S,G) with it -- find_route() allowing it because the
	# valid host test is waived inside the SSM range.
	#
	# The entry that made is what this asserts on rather than the
	# membership: (G,G) is the shape nothing else can produce, and it is
	# the one an RPF lookup for a class D address and a Join naming a
	# multicast source would have been built on.
	print "6. An IGMPv2 report for an SSM group is ignored"
	group_report "$SSM_V2_GROUP" -v 2
	sleep 2
	if has_sg r3 "$SSM_V2_GROUP" "$SSM_V2_GROUP"; then
		fail "R3 built a ($SSM_V2_GROUP,$SSM_V2_GROUP) entry from a v2 report, the group was read as its own source"
	else
		ok "R3 built no entry whose source is the group"
	fi
	# The membership side of the same thing.  $SSM_V2_GROUP rather than
	# $GROUP because a group that already has memberships takes the
	# "found it, reset its timer" path and never reaches the code this is
	# about -- and because assertion 5 leaves a few hundred legitimate
	# sources on $GROUP on purpose, so "no sources" was never the
	# question either.
	if group_sources "$SSM_V2_GROUP" | grep -qx "$SSM_V2_GROUP"; then
		fail "R3 holds $SSM_V2_GROUP as a source of itself, the v2 report's destination was read as one"
	else
		ok "R3 holds no membership whose source is $SSM_V2_GROUP"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# RFC 7761 sec. 4.8.1 rule 3: there is no Register for a group in the
	# SSM range.  send_pim_register() has always refused to build one, so
	# nothing went on the wire -- but process_cache_miss() put the
	# register vif in the oifs of any (S,G) this router is the DR for
	# unless it was the RP, and for an SSM group the RP is the invented
	# link-local address of S1, never this router.  Nothing took it back
	# out either, the Register-Stop that prunes it for an ASM source
	# never arriving for a group nobody is the RP of, so the kernel
	# raised an upcall for every packet of the stream and the daemon
	# dropped each one.
	#
	# R1 is the DR for $SSM_SRC1, so a few packets from it are all this
	# needs; the stream is short because what is asserted is the shape of
	# the entry and not anything that has to be forwarded.
	print "7. A directly connected SSM source gets no register vif"
	box_run ed1 "$MPING" -s -i "${EP}101a" -t 5 -c "$SSM_PKTS" \
		-w $((SSM_PKTS + 10)) "$GROUP" >"$WORKDIR/sender.log" 2>&1 || true
	if ! wait_for 15 has_sg r1 "$SSM_SRC1" "$GROUP"; then
		fail "r1 built no ($SSM_SRC1,$GROUP), the stream never reached its DR"
		return 1
	fi
	if [ "$(route_oifs r1 "$SSM_SRC1" "$GROUP" | cut -c1)" = "o" ]; then
		fail "r1 forwards ($SSM_SRC1,$GROUP) out the register vif, so every packet of it crosses into user space to be dropped"
	else
		ok "r1 keeps the register vif out of the oifs of an SSM source"
	fi

	result
}

# ssm-range: the SSM range moved off 232.0.0.0/8 by pimd.conf.  What makes
# this worth a scenario of its own rather than an ssm run with another
# group is the replacement: both the group that becomes source specific and
# the group that stops being one are asserted, on the same router, from the
# same pair of reports.
#
# A pimd that does not know the keyword never reaches those assertions: an
# unknown command in pimd.conf sets error_flag in config_vifs_from_file()
# and the logit(LOG_ERR) that follows is an exit(), so the run fails at
# assertion 1 with three routers whose pimd is not there to answer.
check_ssm_range() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	# config.c gives every SSM range a static RP at 169.254.0.1, a
	# link-local address that leads nowhere, so that an SSM group
	# resolves to an RP entry without any register ever leaving the
	# router.  Which ranges have one is therefore pimd's own answer to
	# what it considers source specific, before a single report arrives.
	print "2. The configured range has the link-local RP, the default one no longer does"
	if wait_for 30 has_static_rp r3 "$SSMR_RANGE"; then
		ok "R3 holds the static RP 169.254.0.1 for $SSMR_RANGE"
	else
		fail "R3 has no static RP for $SSMR_RANGE, the range was not configured"
	fi
	if has_static_rp r3 "$SSMR_DEFAULT_RANGE"; then
		fail "R3 still has the static RP for $SSMR_DEFAULT_RANGE, the range was added, not replaced"
	else
		ok "$SSMR_DEFAULT_RANGE has no static RP left, the configured range replaced it"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "3. A group in the configured range is source specific"
	ssm_report -t allow "$SSM_SRC1" "$SSM_SRC2"
	if wait_for 15 ssm_count_is 2; then
		ok "R3 holds ($SSM_SRC1,$GROUP) and ($SSM_SRC2,$GROUP)"
	else
		fail "R3 holds $(ssm_sources | tr '\n' ' ')for $GROUP instead of both sources"
	fi
	if group_has_any "$GROUP"; then
		fail "R3 also holds an any-source membership for $GROUP"
	else
		ok "R3 keeps no any-source membership for $GROUP"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# The same report, the same router, a group from the range that is
	# no longer in effect: pimd has to ignore the sources it names and
	# keep the one any-source membership it keeps for any other group.
	print "4. A group in the replaced default range is not"
	group_report "$SSMR_OLD_GROUP" -t allow "$SSM_SRC1" "$SSM_SRC2"
	if wait_for 15 group_has_any "$SSMR_OLD_GROUP"; then
		ok "R3 holds (*,$SSMR_OLD_GROUP), an ordinary any-source membership"
	else
		fail "R3 has no any-source membership for $SSMR_OLD_GROUP"
	fi
	if group_count_is "$SSMR_OLD_GROUP" 0; then
		ok "R3 kept no per-source state for $SSMR_OLD_GROUP"
	else
		fail "R3 still treats $SSMR_OLD_GROUP as SSM, holding $(group_sources "$SSMR_OLD_GROUP" | tr '\n' ' ')"
	fi

	result
}

# Send one IGMPv3 report for a group from ED2
group_report() {
	grp=$1; shift
	box_run ed2 "$IGMPV3" -i "$RCV_ADDR" -g "$grp" "$@" || \
		die "failed sending an IGMPv3 report from ed2"
}

ssm_report() {
	group_report "$GROUP" "$@"
}

# Sources R3 holds for one group.  "show igmp" prints one line per (group,
# source) and "ANY" in the source column for an any-source membership, so
# this lists (S,G) memberships only.
group_sources() {
	pimctl r3 -t show igmp 2>/dev/null | \
		awk -v grp="$1" '$2 == grp && $3 != "ANY" { print $3 }'
}

ssm_sources() {
	group_sources "$GROUP"
}

# The other half of the same listing: has R3 an any-source membership for
# this group, the state it keeps for a group that is not source specific
group_has_any() {
	pimctl r3 -t show igmp 2>/dev/null | \
		awk -v grp="$1" '$2 == grp && $3 == "ANY" { found = 1 } END { exit !found }'
}

# For wait_for(), which needs a command that returns a status
ssm_count_is() {
	[ "$(ssm_sources | wc -l | tr -d ' ')" -eq "$1" ]
}

group_count_is() {
	[ "$(group_sources "$1" | wc -l | tr -d ' ')" -eq "$2" ]
}

# State column of one interface in "pimctl show interface", empty if pimd
# has no VIF by that name at all
iface_state() {
	pimctl "$1" show interface 2>/dev/null | awk -v i="$2" '$1 == i { print $2 }'
}

iface_not_up() {
	[ "$(iface_state "$1" "$2")" != "Up" ]
}

logged() {
	${SUDO} grep -q "$2" "$WORKDIR/$1.log" 2>/dev/null
}

# Which of the groups $3.. interface $2 on router $1 is no longer in,
# printed as a list and empty when it still holds them all.  ifmcstat is
# the only view of this: netstat -gn shows the forwarding cache and the VIF
# table, not the memberships pimd's sockets hold, and pimctl shows what
# pimd believes rather than what the kernel did with it.
#
# Worth asking directly, because everything else that depends on a
# membership outlives it.  A neighbour entry survives its own Hello
# holdtime, 105s, so a router that has just gone deaf still lists every
# neighbour it had, and an assertion that reads one passes for the minutes
# it takes to age out.
missing_groups() {
	mg_box=$1
	mg_if=$2
	shift 2

	# if_memberships() exits non-zero for an interface it cannot read, and
	# the assignment would take "set -e" with it -- inside the command
	# substitution this runs in, that is a subshell leaving quietly and a
	# caller reading an empty answer as "nothing missing".  An interface
	# that cannot be read holds nothing we can prove it holds, so say so.
	mg_held=$(if_memberships "$mg_box" "$mg_if") || mg_held=
	for mg_group in "$@"; do
		echo "$mg_held" | grep -Fqx "$mg_group" || printf '%s ' "$mg_group"
	done
}

# True as soon as any interface in $2 (space separated, on router $1) has
# lost one of $PIM_GROUPS, naming them in $LOST_GROUPS.
#
# For wait_for(), i.e. watched rather than sampled.  pimd finds an interface
# that has gone or moved on its own timer, every TIMER_INTERVAL (5s, see
# src/defs.h), so the leave that can take another interface's membership
# with it does not happen when the address does: a single sample taken in
# between finds everything still in place and proves nothing.
lost_groups() {
	lg_box=$1
	lg_ifs=$2
	LOST_GROUPS=

	for lg_if in $lg_ifs; do
		# shellcheck disable=SC2086
		lg_gone=$(missing_groups "$lg_box" "$lg_if" $PIM_GROUPS)
		if [ -n "$lg_gone" ]; then
			LOST_GROUPS="$LOST_GROUPS$lg_if lost $lg_gone"
		fi
	done

	[ -n "$LOST_GROUPS" ]
}

# Address column of one interface in "pimctl show interface", i.e. the
# address pimd gave the VIF out of the several the interface may carry
iface_addr() {
	pimctl "$1" -t show interface 2>/dev/null | awk -v i="$2" '$1 == i { print $3 }'
}

# Does pimd give interface $2 on router $1 the address $3?  Re-read on every
# call, so it can be polled with wait_for() while a VIF restarts.
iface_is() {
	[ "$(iface_addr "$1" "$2")" = "$3" ]
}

# alias: R1's interface facing the sender carries two addresses, and the
# sender only has one out of the second subnet.  There can be one VIF per
# interface and no more -- MRT_ADD_VIF is keyed on the ifnet, and the VIF
# holds a single local address -- so the second subnet has nowhere to go
# except onto the VIF the first one made, as one of the extra subnets
# pimd.conf calls an "altnet".  config_vifs_from_kernel() (src/config.c)
# used to drop it instead, with an "alias for vif#N?" at debug level, and
# nothing else ever looked at the address again.
#
# That is not cosmetic on BSD.  find_vif_direct_local() (src/vif.c) walks
# the VIF subnets and their altnets, and k_req_incoming()
# (src/routesock.c) asks it before it asks the kernel, precisely because
# a route to a connected subnet carries no gateway: the routing socket
# answers such a lookup with an RPF neighbour of 0.0.0.0, and every
# caller compares that against the source and concludes the source is not
# directly connected.  So with the second subnet dropped, R1 -- the
# designated router for a sender sitting on it -- decides it is not the
# first hop router for that sender at all.  check_register() (src/route.c)
# never encapsulates a thing, no Register reaches the RP, and nothing the
# sender sends is forwarded anywhere.  Assertion 5 is the one that says
# so; assertions 2 and 3 say which of the two subnets became the VIF and
# which became the altnet, so a failure downstream can be read.
#
# Linux is not a witness here: netlink.c answers an RPF lookup for a
# connected destination with the destination as its own RPF neighbour, so
# the whole path is hidden behind the unicast lookup and the scenario
# would pass there whether pimd keeps the alias or not.
check_alias() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. R1 has one VIF on $ALIAS_IF, holding the primary address"
	addr=$(iface_addr r1 "$ALIAS_IF")
	if [ "$addr" = 10.0.1.1 ]; then
		ok "$ALIAS_IF is vif $(vif_index r1 "$ALIAS_IF") with address $addr"
	else
		fail "$ALIAS_IF has address '$addr', want 10.0.1.1"
	fi

	count=$(pimctl r1 -t show interface 2>/dev/null | \
		awk -v i="$ALIAS_IF" '$1 == i { n++ } END { print n + 0 }')
	if [ "$count" -eq 1 ]; then
		ok "no second vif was made for $ALIAS_ADDR"
	else
		fail "$count vifs named $ALIAS_IF, want exactly 1"
	fi

	print "3. R1 kept the aliased subnet as an altnet of that VIF"
	if logged r1 "as altnet $ALIAS_NET"; then
		ok "r1 added $ALIAS_NET as an altnet of $ALIAS_IF"
	else
		fail "r1 never logged an altnet for $ALIAS_NET, see $WORKDIR/r1.log"
	fi

	# Only a domain that never converged is reason to stop here.  A
	# missing altnet is exactly what the rest of the run is about, so it
	# must not take assertion 5 down with it.
	converged=$FAILED

	print "4. PIM converges: neighbors and the RP set"
	if wait_for 60 has_neighbor r1 10.0.12.2; then
		ok "r1 sees r2 (10.0.12.2)"
	else
		fail "r1 never saw r2, PIM hello is not crossing ${EP}112"
	fi
	for r in $ROUTERS; do
		if wait_for 90 has_rp "$r" "$RP_ADDR"; then
			ok "$r learned RP $RP_ADDR"
		else
			fail "$r never learned RP $RP_ADDR (BSR/cand-RP path)"
		fi
	done
	[ "$FAILED" -eq "$converged" ] || return 1

	print "5. Multicast from a sender on the aliased subnet reaches ED2"
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 90 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	sleep 2
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c 40 -w 60 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 || true
	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true

	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
	if [ "$replies" -ge "$MIN_REPLIES" ]; then
		ok "ED1 ($SRC_ADDR) -> $GROUP -> ED2, $replies replies"
	else
		fail "only $replies replies, want >= $MIN_REPLIES, see $WORKDIR/sender.log"
	fi

	print "6. R1 is the first hop router for the aliased source"
	if has_mrt r1 "$SRC_ADDR"; then
		ok "r1 has an (S,G) for source $SRC_ADDR"
	else
		fail "r1 has no (S,G) for $SRC_ADDR"
	fi

	# The incoming interface is the point: the register vif is index 0,
	# and an (S,G) that came in anywhere but $ALIAS_IF means the RPF
	# answer for the source was not the LAN it is actually on.
	iif=$(route_iif r1 "$SRC_ADDR" "$GROUP")
	want=$(vif_index r1 "$ALIAS_IF")
	if [ -n "$iif" ] && [ "$iif" = "$want" ]; then
		ok "r1 (S,G) incoming interface is $ALIAS_IF (vif $iif)"
	else
		fail "r1 (S,G) incoming interface is vif '$iif', want $want ($ALIAS_IF)"
	fi

	if has_mfc r1 "$GROUP"; then
		ok "r1 kernel has an MFC entry for $GROUP"
	else
		fail "r1 kernel MFC is empty, pimd never pushed the route down"
	fi

	# The Address List, read by tcpdump rather than by pimd: two pimds
	# share one reading of the option, so R2 understanding R1 says
	# nothing about whether what R1 put on the wire is RFC 7761's.  The
	# secondary address appears nowhere else in a Hello from R1, the IP
	# source being the primary one.  The filter is on the PIM type nibble,
	# a Join/Prune from R1 going to the same group; pimd sends no IP
	# options, so the PIM header is at byte 20.  tcpdump prints the
	# addresses of the option only from -vv up.
	print "7. R1's Hello on $ALIAS_UP_IF lists its secondary address"
	box_run r2 timeout 45 tcpdump -l -c 1 -nvvi "${EPU}112b" \
		"ip proto 103 and src 10.0.12.1 and ip[20] & 0x0f = 0" \
		>"$WORKDIR/hello.txt" 2>/dev/null || true
	if grep -q "Address List" "$WORKDIR/hello.txt" && \
	   grep -q "$ALIAS_UP_ADDR" "$WORKDIR/hello.txt"; then
		ok "tcpdump decodes an Address List holding $ALIAS_UP_ADDR"
	else
		fail "no Address List with $ALIAS_UP_ADDR in R1's Hello, see $WORKDIR/hello.txt"
	fi

	print "8. R2 maps the secondary address to R1"
	if wait_for 45 has_secaddr r2 10.0.12.1 "$ALIAS_UP_ADDR"; then
		ok "r2 lists $ALIAS_UP_ADDR as a secondary address of neighbour 10.0.12.1"
	else
		fail "r2 has no secondary address $ALIAS_UP_ADDR for 10.0.12.1"
	fi
	if has_secaddr r2 10.0.12.1 10.0.12.1; then
		fail "r2 lists R1's primary address as a secondary of itself"
	else
		ok "the primary address is not among them"
	fi

	# What the mapping is for.  R2 is the RP, and its route to the source
	# names $ALIAS_UP_ADDR: without the mapping that is "NOT A PIM
	# ROUTER", no (S,G) Join reaches R1, and the stream arrives only
	# register encapsulated -- which is why assertion 5 passes either
	# way and cannot be the witness.  R1 forwarding natively onto the
	# link to R2 is the Join having arrived.
	print "9. The RP's (S,G) Join reaches R1 through the secondary address"
	iif=$(route_iif r2 "$SRC_ADDR" "$GROUP")
	want=$(vif_index r2 "${EPU}112b")
	if [ -n "$iif" ] && [ "$iif" = "$want" ]; then
		ok "r2 (S,G) incoming interface is ${EPU}112b (vif $iif)"
	else
		fail "r2 (S,G) incoming interface is vif '$iif', want $want (${EPU}112b)"
	fi
	if logged r2 "For src $SRC_ADDR, iif is ${EPU}112b, next hop router is $ALIAS_UP_ADDR: NOT A PIM ROUTER"; then
		fail "r2 did not map $ALIAS_UP_ADDR to a neighbour at some point, see $WORKDIR/r2.log"
	else
		ok "r2 never took $ALIAS_UP_ADDR for a router that does not speak PIM"
	fi
	oifs=$(route_oifs r1 "$SRC_ADDR" "$GROUP")
	if map_isset r1 "$ALIAS_UP_IF" "$oifs"; then
		ok "r1 (S,G) forwards onto $ALIAS_UP_IF, R2's Join arrived"
	else
		fail "r1 (S,G) outgoing map '$oifs' does not include $ALIAS_UP_IF, no Join from R2"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	dprint "--- r1: $ALIAS_IF ---"
	box_if_show r1 "$ALIAS_IF" 2>&1 || true
	for r in $ROUTERS; do
		dprint "--- $r: pimctl show pim detail ---"
		pimctl "$r" show pim detail 2>&1 | tail -40 || true
	done
	return 1
}

# IGMP version column of one interface in "pimctl show igmp interface",
# empty if pimd has no VIF by that name.  The table has one row per VIF and
# every column of it is always filled, so the version is simply the fifth
# field: Interface State Querier Timeout Version Groups.
iface_igmp_version() {
	pimctl "$1" -t show igmp interface 2>/dev/null | \
		awk -v i="$2" '$1 == i { print $5 }'
}

# How many VIFs router $1 has, the register vif excluded -- "show
# interface" leaves that one out, one row per VIF for the rest.  What this
# is for is telling a VIF that came back on the slot it had from one that
# was appended beside the stale entry of an interface that went away.
iface_count() {
	pimctl "$1" -t show interface 2>/dev/null | awk 'NF { n++ } END { print n + 0 }'
}

# An interface that appears under a running pimd.  init_vifs()
# (src/vif.c) used to be the only caller of config_vifs_from_kernel()
# (src/config.c), so the vif table was whatever the kernel had at
# start-up: an interface configured afterwards never became a VIF, and
# the only way back to a correct table was a restart.  The rc(8) ordering
# that turned this up is in the header, and it is the ordinary case on
# anything whose links are negotiated -- PPP, L2TP, a tunnel that comes
# up, a VLAN added to a router in service.
#
# The assertions are written against both routers rather than one, and
# against the kernel as well as against pimd's own table: a VIF that pimd
# lists but never handed to the kernel forwards nothing, and a VIF that
# joined no groups hears no Hello, so neither shows up as anything but a
# missing adjacency later on.
check_ifnew() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	# The state every later assertion is compared against: the link R1
	# and R2 have had all along, and what each router's vif table looked
	# like before anything was added to it.
	print "2. R1 and R2 are adjacent over the link they started with"
	if wait_for 60 has_neighbor r1 "$IFNEW_KEPT_ADDR"; then
		ok "r1 has R2 ($IFNEW_KEPT_ADDR) as a neighbour"
	else
		fail "r1 never saw R2 on the link it started with, nothing to compare against"
		return 1
	fi
	r1_vifs=$(iface_count r1)
	r2_vifs=$(iface_count r2)
	dprint "r1 has $r1_vifs VIFs, r2 has $r2_vifs"

	print "3. Neither router has a VIF on an interface that does not exist"
	for i in "$IFNEW_IF" "$IFNEW_OFF_IF"; do
		if has_iface r1 "$i"; then
			fail "r1 already has a VIF on $i, which nothing has created"
		else
			ok "r1: no VIF on $i"
		fi
	done
	if has_iface r2 "$IFNEW_PEER_IF"; then
		fail "r2 already has a VIF on $IFNEW_PEER_IF"
	else
		ok "r2: no VIF on $IFNEW_PEER_IF"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "4. A second R1-R2 link is created and addressed under both daemons"
	box_link_add "$IFNEW_EP" r1 r2 || die "failed creating $IFNEW_EP"
	box_addr_add r1 "$IFNEW_IF" "$IFNEW_ADDR/$IFNEW_PREFIX"
	box_if_up r1 "$IFNEW_IF"
	box_addr_add r2 "$IFNEW_PEER_IF" "$IFNEW_PEER_ADDR/$IFNEW_PREFIX"
	box_if_up r2 "$IFNEW_PEER_IF"

	# R1's other new interface, the one r1.conf disables.  Created in the
	# same breath as the link above so that one wait covers both: the
	# assertion that it gets no VIF is only worth anything once the
	# rescan that gave the other one a VIF has run.
	box_link_add "$IFNEW_OFF_EP" r1 - || die "failed creating $IFNEW_OFF_EP"
	box_addr_add r1 "$IFNEW_OFF_IF" "$IFNEW_OFF_ADDR/$IFNEW_PREFIX"
	box_if_up r1 "$IFNEW_OFF_IF"

	print "5. Both routers give the new link a VIF, with no restart"
	if wait_for "$IFNEW_WAIT" has_iface r1 "$IFNEW_IF"; then
		ok "r1: VIF on $IFNEW_IF"
	else
		fail "r1: no VIF on $IFNEW_IF after ${IFNEW_WAIT}s, see $WORKDIR/r1.log"
	fi
	if wait_for "$IFNEW_WAIT" has_iface r2 "$IFNEW_PEER_IF"; then
		ok "r2: VIF on $IFNEW_PEER_IF"
	else
		fail "r2: no VIF on $IFNEW_PEER_IF after ${IFNEW_WAIT}s, see $WORKDIR/r2.log"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	if [ "$(iface_state r1 "$IFNEW_IF")" = Up ] && iface_is r1 "$IFNEW_IF" "$IFNEW_ADDR"; then
		ok "r1: $IFNEW_IF is Up on $IFNEW_ADDR"
	else
		fail "r1: $IFNEW_IF reads $(iface_state r1 "$IFNEW_IF") on $(iface_addr r1 "$IFNEW_IF")"
	fi
	if [ "$(iface_state r2 "$IFNEW_PEER_IF")" = Up ] && \
	   iface_is r2 "$IFNEW_PEER_IF" "$IFNEW_PEER_ADDR"; then
		ok "r2: $IFNEW_PEER_IF is Up on $IFNEW_PEER_ADDR"
	else
		fail "r2: $IFNEW_PEER_IF reads $(iface_state r2 "$IFNEW_PEER_IF") on $(iface_addr r2 "$IFNEW_PEER_IF")"
	fi

	# A daemon that restarted would have a correct table too, and would
	# have thrown every adjacency and every route away to get it
	if logged r1 "restarting"; then
		fail "r1: pimd restarted, the table was not rescanned"
	else
		ok "r1: pimd never restarted"
	fi

	print "6. The VIF reached the kernel, not just pimd's table"
	idx=$(vif_index r1 "$IFNEW_IF")
	if [ -z "$idx" ]; then
		fail "r1: $IFNEW_IF has no vif index"
	elif [ "$(kern_vif_addr r1 "$idx")" = "$IFNEW_ADDR" ]; then
		ok "r1: kernel vif $idx is $IFNEW_ADDR"
	else
		fail "r1: kernel vif $idx reads $(kern_vif_addr r1 "$idx"), expected $IFNEW_ADDR"
	fi

	print "7. The groups pimd joins on a link it runs PIM on were joined"
	# shellcheck disable=SC2086
	missing=$(missing_groups r1 "$IFNEW_IF" $PIM_GROUPS)
	if [ -z "$missing" ]; then
		ok "r1: $IFNEW_IF is in $PIM_GROUPS"
	else
		fail "r1: $IFNEW_IF never joined $missing"
	fi

	print "8. A PIM adjacency forms over the new link, both ways"
	if wait_for 60 has_neighbor r1 "$IFNEW_PEER_ADDR"; then
		ok "r1 has $IFNEW_PEER_ADDR as a neighbour"
	else
		fail "r1 never saw R2 on $IFNEW_IF, see $WORKDIR/r1.log"
	fi
	if wait_for 60 has_neighbor r2 "$IFNEW_ADDR"; then
		ok "r2 has $IFNEW_ADDR as a neighbour"
	else
		fail "r2 never saw R1 on $IFNEW_PEER_IF, see $WORKDIR/r2.log"
	fi

	print "9. r1.conf was applied to the interfaces it names"
	# The negative half: an interface pimd.conf disables gets no VIF,
	# though the kernel has it and it is addressed like the other one
	if has_iface r1 "$IFNEW_OFF_IF"; then
		fail "r1: $IFNEW_OFF_IF got a VIF, 'phyint $IFNEW_OFF_IF disable' was not read"
	else
		ok "r1: no VIF on $IFNEW_OFF_IF, the phyint line disabling it was read"
	fi
	# ... and the positive one, on the interface the same file configures
	# rather than disables.  R2 has no phyint line at all for its end, so
	# it prints what an unconfigured VIF does and tells a version that was
	# applied from one that is merely the default.
	if [ "$(iface_igmp_version r1 "$IFNEW_IF")" = 2 ]; then
		ok "r1: $IFNEW_IF runs IGMPv2, as 'phyint $IFNEW_IF igmpv2' asks"
	else
		fail "r1: $IFNEW_IF runs IGMPv$(iface_igmp_version r1 "$IFNEW_IF"), the phyint line was not applied"
	fi
	if [ "$(iface_igmp_version r2 "$IFNEW_PEER_IF")" = 3 ]; then
		ok "r2: $IFNEW_PEER_IF runs IGMPv3, the default for a VIF nothing configures"
	else
		fail "r2: $IFNEW_PEER_IF runs IGMPv$(iface_igmp_version r2 "$IFNEW_PEER_IF"), expected the v3 default"
	fi

	print "10. The link the routers started with was not disturbed"
	if has_neighbor r1 "$IFNEW_KEPT_ADDR"; then
		ok "r1 still has R2 ($IFNEW_KEPT_ADDR) on the original link"
	else
		fail "r1 lost R2 on the original link while the new one was added"
	fi
	# shellcheck disable=SC2086
	if lost_groups r1 "${EP}101b ${EP}112a"; then
		fail "r1: ${LOST_GROUPS}- the rescan took a membership off another interface"
	else
		ok "r1: the interfaces it started with kept $PIM_GROUPS"
	fi
	if [ "$(iface_count r1)" -eq $((r1_vifs + 1)) ]; then
		ok "r1 has one VIF more than it started with"
	else
		fail "r1 has $(iface_count r1) VIFs, expected $((r1_vifs + 1))"
	fi

	print "11. The same link, destroyed and built again, comes back on its own slot"
	box_if_destroy r2 "$IFNEW_PEER_IF" || die "failed destroying $IFNEW_PEER_IF on r2"
	if wait_for "$IFNEW_WAIT" iface_not_up r1 "$IFNEW_IF"; then
		ok "r1: $IFNEW_IF taken out of service"
	else
		fail "r1: $IFNEW_IF still reads Up, the VIF was left in service"
	fi
	if ! pimd_is_up r1; then
		fail "r1: pimd exited when the new link went away, see $WORKDIR/r1.log"
		return 1
	fi

	box_link_add "$IFNEW_EP" r1 r2 || die "failed recreating $IFNEW_EP"
	box_addr_add r1 "$IFNEW_IF" "$IFNEW_ADDR/$IFNEW_PREFIX"
	box_if_up r1 "$IFNEW_IF"
	box_addr_add r2 "$IFNEW_PEER_IF" "$IFNEW_PEER_ADDR/$IFNEW_PREFIX"
	box_if_up r2 "$IFNEW_PEER_IF"

	if wait_for "$IFNEW_WAIT" iface_is r1 "$IFNEW_IF" "$IFNEW_ADDR"; then
		ok "r1: $IFNEW_IF is back on $IFNEW_ADDR"
	else
		fail "r1: $IFNEW_IF did not come back, it reads $(iface_state r1 "$IFNEW_IF")"
	fi
	# The point of the flap: a rescan that appended a slot instead of
	# finding the one the name already had would reach MAXVIFS on a
	# router whose links come and go
	if [ "$(iface_count r1)" -eq $((r1_vifs + 1)) ]; then
		ok "r1 still has $((r1_vifs + 1)) VIFs, the slot was reused"
	else
		fail "r1 has $(iface_count r1) VIFs after one flap, expected $((r1_vifs + 1))"
	fi
	if [ "$(vif_index r1 "$IFNEW_IF")" = "$idx" ]; then
		ok "r1: $IFNEW_IF came back as vif $idx"
	else
		fail "r1: $IFNEW_IF came back as vif $(vif_index r1 "$IFNEW_IF"), was $idx"
	fi
	if wait_for 60 has_neighbor r1 "$IFNEW_PEER_ADDR"; then
		ok "r1 has $IFNEW_PEER_ADDR as a neighbour again"
	else
		fail "r1 never saw R2 on $IFNEW_IF again, see $WORKDIR/r1.log"
	fi

	result
}

check_ifgone() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. R1 has a VIF on the interface that is about to go away"
	if wait_for 30 has_iface r1 "$IFGONE_IF" && \
	   [ "$(iface_state r1 "$IFGONE_IF")" = "Up" ]; then
		ok "r1: $IFGONE_IF ($IFGONE_ADDR) is up"
	else
		fail "r1: no VIF on $IFGONE_IF to take away"
		return 1
	fi

	# Taken before the interface goes, so assertion 6 knows whether the
	# register VIF had anything to fall back from in the first place
	reg_before=$(kern_vif_addr r1 0)
	dprint "register VIF sits on ${reg_before:-none}"

	print "3. The interface is destroyed under pimd"
	box_if_destroy ed1 "$IFGONE_PEER_IF" || \
		die "failed destroying $IFGONE_PEER_IF on ed1"
	# age_vifs() polls every TIMER_INTERVAL (5s), src/defs.h
	if wait_for 30 iface_not_up r1 "$IFGONE_IF"; then
		ok "r1: $IFGONE_IF taken out of service"
	else
		fail "r1: $IFGONE_IF still reads $(iface_state r1 "$IFGONE_IF"), VIF left in service"
	fi

	# Before anything else: an exited pimd answers no question below
	print "4. pimd survived the removal"
	if pimctl r1 show status >/dev/null 2>&1; then
		ok "r1: pimd still answers on its pimctl socket"
	else
		fail "r1: pimd exited when the interface went away, see $WORKDIR/r1.log"
		return 1
	fi

	print "5. The removal was logged, and not as a fatal ioctl error"
	if logged r1 "Interface $IFGONE_IF has gone"; then
		ok "r1: logged $IFGONE_IF out of service"
	else
		fail "r1: nothing logged about $IFGONE_IF"
	fi
	if logged r1 "ioctl SIOCGIFFLAGS"; then
		fail "r1: SIOCGIFFLAGS errno not recognised as a removed interface"
	else
		ok "r1: no SIOCGIFFLAGS error, ENXIO read as a removed interface"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "6. The register VIF moved off the address that went away"
	reg_after=$(kern_vif_addr r1 0)
	if [ "$reg_before" != "$IFGONE_ADDR" ]; then
		dprint "register VIF was on ${reg_before:-none}, not $IFGONE_ADDR, nothing to move"
	elif [ "$reg_after" = "$IFGONE_KEPT" ]; then
		ok "register VIF re-homed from $IFGONE_ADDR to $reg_after"
	else
		fail "register VIF reads ${reg_after:-none}, expected $IFGONE_KEPT"
	fi

	print "7. R1 still runs PIM on the link it has left"
	if wait_for 60 has_neighbor r1 10.0.12.2; then
		ok "r1 still has R2 (10.0.12.2) as a neighbour"
	else
		fail "r1 lost its remaining PIM adjacency"
	fi

	# The adjacency above is the symptom; this is the cause, and it is
	# the half that shows up immediately.  The leave issued for the
	# interface that went names an address the kernel can no longer
	# place, and on *BSD that is not refused: in_mcast.c matches the
	# group on any interface and drops the first membership it finds,
	# which is this one.
	print "8. The link R1 kept is still in the groups pimd joined"
	if wait_for "$GROUP_WATCH" lost_groups r1 "$IFGONE_KEPT_IF"; then
		fail "r1: ${LOST_GROUPS}- the leave for $IFGONE_IF took them"
	else
		ok "r1: $IFGONE_KEPT_IF held $PIM_GROUPS for ${GROUP_WATCH}s after $IFGONE_IF went"
	fi

	# The other half of keeping the slot.  A VIF that is out of service
	# holds the address and subnet it had when its interface went, and
	# scan_vifs_from_kernel() (src/config.c) used to let it go on owning
	# that subnet: the interface the address had moved to was refused a
	# VIF, "Ignoring X, same subnet as Y", naming an interface the kernel
	# no longer has as the reason, and only a restart got it back.
	print "9. The subnet the interface took with it is free for another one"
	vifs_before=$(iface_count r1)
	box_link_add "$IFGONE_NEW_EP" r1 - || die "failed creating $IFGONE_NEW_EP"
	box_addr_add r1 "$IFGONE_NEW_IF" "$IFGONE_NEW_ADDR/$IFGONE_NEW_PREFIX"
	box_if_up r1 "$IFGONE_NEW_IF"

	if wait_for "$IFGONE_NEW_WAIT" iface_is r1 "$IFGONE_NEW_IF" "$IFGONE_NEW_ADDR"; then
		ok "r1: VIF on $IFGONE_NEW_IF ($IFGONE_NEW_ADDR), out of $IFGONE_ADDR's subnet"
	else
		fail "r1: no VIF on $IFGONE_NEW_IF after ${IFGONE_NEW_WAIT}s, see $WORKDIR/r1.log"
	fi
	if logged r1 "Ignoring $IFGONE_NEW_IF, same subnet as"; then
		fail "r1: $IFGONE_NEW_IF refused, $IFGONE_IF owns the subnet after going away"
	else
		ok "r1: nothing refused $IFGONE_NEW_IF the subnet"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	new_idx=$(vif_index r1 "$IFGONE_NEW_IF")
	if [ -n "$new_idx" ] && [ "$(kern_vif_addr r1 "$new_idx")" = "$IFGONE_NEW_ADDR" ]; then
		ok "r1: kernel vif $new_idx is $IFGONE_NEW_ADDR"
	else
		fail "r1: kernel vif ${new_idx:-none} reads $(kern_vif_addr r1 "${new_idx:-0}"), expected $IFGONE_NEW_ADDR"
	fi
	# A name pimd has never seen takes a slot of its own, beside the one
	# $IFGONE_IF keeps for its own name to come back to (see ifnew)
	if has_iface r1 "$IFGONE_IF"; then
		ok "r1: $IFGONE_IF kept its slot, out of service"
	else
		fail "r1: $IFGONE_IF lost its slot to $IFGONE_NEW_IF"
	fi
	if [ "$(iface_count r1)" -eq $((vifs_before + 1)) ]; then
		ok "r1 has one VIF more than before $IFGONE_NEW_IF appeared"
	else
		fail "r1 has $(iface_count r1) VIFs, expected $((vifs_before + 1))"
	fi

	# The control for the assertion above, and the reason it is asked of
	# the addresses the kernel has rather than of the VIF flags: an
	# interface that is merely down still owns its subnet, and has to keep
	# it, or the subnet is handed to a second interface while the first is
	# only waiting to come back up.
	print "10. An interface that is only down keeps its subnet"
	box_if_down r1 "$IFGONE_NEW_IF" || die "failed taking $IFGONE_NEW_IF down on r1"
	if wait_for "$IFGONE_NEW_WAIT" iface_not_up r1 "$IFGONE_NEW_IF"; then
		ok "r1: $IFGONE_NEW_IF taken out of service, its interface still there"
	else
		fail "r1: $IFGONE_NEW_IF still reads Up after being taken down"
		return 1
	fi

	box_link_add "$IFGONE_DUP_EP" r1 - || die "failed creating $IFGONE_DUP_EP"
	box_addr_add r1 "$IFGONE_DUP_IF" "$IFGONE_DUP_ADDR/$IFGONE_NEW_PREFIX"
	box_if_up r1 "$IFGONE_DUP_IF"

	# Asked of the log rather than of the clock: the refusal is a line of
	# its own, so there is no need to wait out a rescan that may already
	# have run to call the VIF missing.
	if wait_for "$IFGONE_NEW_WAIT" logged r1 "Ignoring $IFGONE_DUP_IF, same subnet as $IFGONE_NEW_IF"; then
		ok "r1: refused $IFGONE_DUP_IF the subnet $IFGONE_NEW_IF still owns"
	else
		fail "r1: nothing refused $IFGONE_DUP_IF, see $WORKDIR/r1.log"
	fi
	if has_iface r1 "$IFGONE_DUP_IF"; then
		fail "r1: $IFGONE_DUP_IF got a VIF on a subnet $IFGONE_NEW_IF still owns"
	else
		ok "r1: no VIF on $IFGONE_DUP_IF"
	fi

	result
}

# An interface renumbered under a running pimd.  The VIF keeps naming an
# address the kernel no longer has unless something notices: pimd goes on
# sourcing PIM from it, and the neighbours hold it, and may elect it DR, for
# the whole 105 second holdtime, while its own sends leave by whatever route
# the kernel picks.  RFC 7761 sec. 4.3.1 asks for a Hello with a zero
# HoldTime carrying the old address and a Hello carrying the new one, which
# is what taking the VIF out of service and back in does here.
#
# What this exercises, in src/vif.c: check_vif_addrs() walking getifaddrs()
# the way config_vifs_from_kernel() does, renumber_vif() deciding an address
# really changed, and the stop_vif()/start_vif() pair that makes the group
# memberships, the kernel VIF and the routing entries follow it.
check_renumber() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. R2 and R3 are neighbours at the address about to change"
	if wait_for 60 has_neighbor "$RENUM_PEER" "$RENUM_OLD"; then
		ok "$RENUM_PEER: R2 is a PIM neighbour at $RENUM_OLD"
	else
		fail "$RENUM_PEER: no adjacency with R2 to renumber, see $WORKDIR/$RENUM_PEER.log"
		return 1
	fi
	if [ "$(iface_addr r2 "$RENUM_IF")" = "$RENUM_OLD" ]; then
		ok "r2: VIF on $RENUM_IF reads $RENUM_OLD"
	else
		fail "r2: VIF on $RENUM_IF reads $(iface_addr r2 "$RENUM_IF"), expected $RENUM_OLD"
		return 1
	fi

	print "3. The address is changed under pimd"
	box_addr_del r2 "$RENUM_IF" "$RENUM_OLD" || \
		die "failed removing $RENUM_OLD from $RENUM_IF on r2"
	box_addr_add r2 "$RENUM_IF" "$RENUM_NEW/24" || \
		die "failed adding $RENUM_NEW to $RENUM_IF on r2"
	# The unicast routing follows the address, as it would in the field:
	# R3 reaches the source and the RP through the gateway that just moved.
	for net in 10.0.1.0/24 10.0.12.0/24; do
		box_route_change "$RENUM_PEER" "$net" "$RENUM_NEW" >/dev/null 2>&1 || \
			dprint "$RENUM_PEER: no route to $net to repoint, continuing"
	done
	dprint "r2: $RENUM_IF is now $RENUM_NEW"

	print "4. pimd noticed, and said so"
	# check_vif_state() runs from age_vifs() every TIMER_INTERVAL (5s),
	# src/defs.h, so this is a handful of polls at most
	if wait_for 30 logged r2 "renumbered from $RENUM_OLD to $RENUM_NEW"; then
		ok "r2: logged the renumbering of $RENUM_IF"
	else
		fail "r2: nothing logged, the address change went unnoticed"
	fi

	print "5. pimd survived taking the VIF out of service and back in"
	if pimctl r2 show status >/dev/null 2>&1; then
		ok "r2: pimd still answers on its pimctl socket"
	else
		fail "r2: pimd exited during the renumbering, see $WORKDIR/r2.log"
		return 1
	fi

	print "6. The VIF is back in service on the new address"
	if wait_for 30 iface_is r2 "$RENUM_IF" "$RENUM_NEW"; then
		ok "r2: VIF on $RENUM_IF reads $RENUM_NEW"
	else
		fail "r2: VIF on $RENUM_IF reads $(iface_addr r2 "$RENUM_IF"), expected $RENUM_NEW"
	fi
	if [ "$(iface_state r2 "$RENUM_IF")" = "Up" ]; then
		ok "r2: $RENUM_IF is up again"
	else
		fail "r2: $RENUM_IF reads $(iface_state r2 "$RENUM_IF") after the restart"
	fi
	if [ "$(kern_vif_addr r2 "$(vif_index r2 "$RENUM_IF")")" = "$RENUM_NEW" ]; then
		ok "r2: the kernel VIF moved to $RENUM_NEW as well"
	else
		fail "r2: kernel VIF still reads $(kern_vif_addr r2 "$(vif_index r2 "$RENUM_IF")")"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "7. The neighbour on the far side learns the new address"
	# start_vif() sends a Hello as soon as the VIF is back, so this does
	# not wait for a periodic one
	if wait_for 60 has_neighbor "$RENUM_PEER" "$RENUM_NEW"; then
		ok "$RENUM_PEER: R2 is a PIM neighbour at $RENUM_NEW"
	else
		fail "$RENUM_PEER: never heard from R2 at $RENUM_NEW, see $WORKDIR/$RENUM_PEER.log"
	fi
	# The goodbye Hello is sent with the old address, which the kernel no
	# longer has, so it may not leave at all -- a poll cannot get ahead of
	# an address that has already gone.  Whether R1 drops $RENUM_OLD now
	# or ages it out is therefore not asserted, only reported.
	if has_neighbor "$RENUM_PEER" "$RENUM_OLD"; then
		dprint "$RENUM_PEER: still holds the old $RENUM_OLD, ages out after the holdtime"
	else
		dprint "$RENUM_PEER: dropped $RENUM_OLD, the zero-holdtime Hello got through"
	fi

	print "8. The other VIF on the same router was left alone"
	if has_neighbor r2 "$RENUM_KEPT"; then
		ok "r2: still has R1 ($RENUM_KEPT) as a neighbour"
	else
		fail "r2: lost its adjacency with R1, the restart was not confined to $RENUM_IF"
	fi

	# Both halves of the same leave.  The renumbered VIF is stopped with
	# the address that has just been deleted, so the kernel cannot place
	# it: the membership it should have dropped stays on $RENUM_IF, and
	# another interface's is dropped in its place.  The neighbour above
	# says nothing about either -- it lives on for its holdtime.
	print "9. Both links hold every group after the renumbering"
	if wait_for "$GROUP_WATCH" lost_groups r2 "$RENUM_KEPT_IF $RENUM_IF"; then
		fail "r2: ${LOST_GROUPS}- the leave for $RENUM_IF named an address the kernel could not place"
	else
		ok "r2: $RENUM_KEPT_IF and $RENUM_IF both held $PIM_GROUPS for ${GROUP_WATCH}s"
	fi
	if logged r2 "Cannot join group"; then
		fail "r2: a group re-join was refused, the old membership was never dropped"
	else
		ok "r2: every group was re-joined, none was still held"
	fi

	result
}

check_keepalive() {
	print "1. pimd is alive on R1"
	if wait_for "$PIMD_START_WAIT" pimd_is_up r1; then
		ok "r1: pimd answers on its pimctl socket"
	else
		fail "r1: pimd not answering, see $WORKDIR/r1.log"
		return 1
	fi

	print "2. R1 elected itself RP for the groups its source sends to"
	if wait_for 90 has_rp r1 10.0.1.1; then
		ok "r1 is the RP (10.0.1.1)"
	else
		fail "r1 never became RP, see $WORKDIR/r1.log"
		return 1
	fi

	print "3. R1 learns all $KEEP_NUM sources"
	if wait_for 60 all_sources_up; then
		ok "r1 has (S,G) entries for $(sources | tr '\n' ' ')"
	else
		fail "r1 only has $(sources | wc -l | tr -d ' ')/$KEEP_NUM (S,G) entries"
		return 1
	fi

	print "4. The sources stay put for ${KEEP_SECONDS}s while they keep sending"
	deadline=$(($(date +%s) + KEEP_SECONDS))
	samples=0
	missing=0
	dead=0
	worst=$KEEP_NUM
	while [ "$(date +%s)" -lt "$deadline" ]; do
		timers=$(source_timers)
		n=$(echo "$timers" | grep -c . || true)
		samples=$((samples + 1))

		if [ "$n" -ne "$KEEP_NUM" ]; then
			missing=$((missing + 1))
			[ "$n" -lt "$worst" ] && worst=$n
		fi

		# An entry whose keepalive timer is 0 is one age_routes()
		# run away from being deleted, however fast the next cache
		# miss brings it back
		if echo "$timers" | awk '$2 == 0 { found = 1 } END { exit !found }'; then
			dead=$((dead + 1))
		fi

		sleep 5
	done

	if [ "$missing" -eq 0 ]; then
		ok "all $KEEP_NUM sources present in every one of $samples samples"
	else
		fail "sources vanished in $missing of $samples samples, down to $worst/$KEEP_NUM"
	fi

	if [ "$dead" -eq 0 ]; then
		ok "every (S,G) kept a running entry timer in all $samples samples"
	else
		fail "(S,G) entry timer was 0, so the entry was being deleted and recreated, in $dead of $samples samples"
	fi

	# local-sg-limit: every group a directly connected sender names makes
	# R1 hold an (S,G), a source and a group entry and a kernel cache
	# entry, so the number is capped.  Step 4 was the control, the groups
	# that fit being refreshed for longer than PIM_DATA_TIMEOUT at the
	# limit; the cache misses logged for the flood are the proof its
	# packets reached R1 at all.
	print "5. local-sg-limit $KEEP_NUM keeps a flood of $KEEP_FLOOD_NUM more groups out"
	m1=$(log_lines r1)
	box_daemon ed1 "$WORKDIR/msend-flood.pid" "$WORKDIR/msend-flood.log" \
		"$MSEND" "$SRC_ADDR" "$KEEP_FLOOD_GROUP" "$KEEP_FLOOD_NUM"
	if ! wait_for 15 log_since r1 "$m1" "Cache miss, src $SRC_ADDR, dst $KEEP_FLOOD_GROUP,"; then
		fail "r1 logged no cache miss for $KEEP_FLOOD_GROUP, the flood is not reaching it"
	else
		if wait_for 10 log_since r1 "$m1" "Not holding ($SRC_ADDR,$KEEP_FLOOD_GROUP), local-sg-limit $KEEP_NUM reached"; then
			ok "r1 refused ($SRC_ADDR,$KEEP_FLOOD_GROUP) at local-sg-limit $KEEP_NUM"
		else
			fail "r1 did not refuse ($SRC_ADDR,$KEEP_FLOOD_GROUP) with $KEEP_NUM entries held"
		fi
		if logged r1 "local-sg-limit $KEEP_NUM reached, no more"; then
			ok "r1 warned that local-sg-limit was reached"
		else
			fail "r1 reached local-sg-limit without the warning"
		fi
		# Long enough for every flood group to have missed several times
		sleep 10
		held=$(sources | tr '\n' ' ')
		if [ "$(sources | wc -l)" -eq "$KEEP_NUM" ] && ! sources | grep -q "^${KEEP_FLOOD_GROUP%.*}\."; then
			ok "r1 still holds exactly its $KEEP_NUM groups under the flood: $held"
		else
			fail "r1 holds '$held' under the flood, expected the $KEEP_NUM groups from $KEEP_GROUP"
		fi
		if pimctl r1 show status 2>/dev/null | grep -q "^Local (S,G) entries *: $KEEP_NUM of $KEEP_NUM\$"; then
			ok "r1 reports $KEEP_NUM of $KEEP_NUM local (S,G) entries"
		else
			fail "r1 reports '$(pimctl r1 show status 2>/dev/null | grep '^Local (S,G)')'"
		fi
	fi

	# The count is given back where an entry is freed, and a reload frees
	# them all: with the flood still on, the slots have to fill again, by
	# whichever groups miss first.  A count that leaked would stay at the
	# limit with nothing behind it and nothing new admitted.
	print "6. A reload gives the local-sg-limit count back"
	if ! pimctl r1 restart >/dev/null 2>&1; then
		fail "r1 did not take pimctl restart"
	elif wait_for 90 all_sources_up && \
	     pimctl r1 show status 2>/dev/null | grep -q "^Local (S,G) entries *: $KEEP_NUM of $KEEP_NUM\$"; then
		sleep 5
		if [ "$(sources | wc -l)" -eq "$KEEP_NUM" ]; then
			ok "r1 filled its $KEEP_NUM slots again after the reload and no more: $(sources | tr '\n' ' ')"
		else
			fail "r1 holds $(sources | wc -l | tr -d ' ') entries after the reload, of a limit of $KEEP_NUM"
		fi
	else
		fail "r1 holds $(sources | wc -l | tr -d ' ') entries after the reload and reports '$(pimctl r1 show status 2>/dev/null | grep '^Local (S,G)')'"
	fi
	${SUDO} pkill -F "$WORKDIR/msend-flood.pid" 2>/dev/null || true

	if [ "$FAILED" -ne 0 ]; then
		dprint "--- r1: pimctl show mrt detail ---"
		pimctl r1 show mrt detail 2>&1 | tail -40 || true
		dprint "--- cache misses logged on r1: $(${SUDO} grep -c "Cache miss" "$WORKDIR/r1.log" 2>/dev/null || echo 0) ---"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	return 1
}

# Issue #243: R3 is the RP and the last hop router at once, and the source
# is remote, behind R1.  R3's (*,G) has the register vif as its incoming
# interface because the RP is itself (set_incoming(), PIM_IIF_RP), R1
# encapsulates the source to it, and the traffic then has to come back out
# of the register vif and down to the directly connected member on
# epair203a.  Every reporter on the issue says it does not: their receivers
# on the RP's own LAN see nothing from the remote source, while the
# opposite direction works, and moving the RP moves the broken direction.
#
# Their RP dumps show the (S,G) for the remote source stuck with the
# register vif as incoming interface, no CACHE flag, and the first hop
# router still registering.  So there are three separate things to check
# and they can fail independently: whether packets arrive at all, whether
# the RP ever leaves the register vif for a native iif, and whether pimd
# pushed anything down to the kernel MFC.
check_rp_lasthop() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. R3 is the RP, and R1 knows where to send its registers"
	if wait_for 90 has_rp r3 "$RPLH_ADDR"; then
		ok "r3 elected itself RP ($RPLH_ADDR)"
	else
		fail "r3 never became RP, see $WORKDIR/r3.log"
		return 1
	fi
	if wait_for 90 has_rp r1 "$RPLH_ADDR"; then
		ok "r1 learned RP $RPLH_ADDR"
	else
		fail "r1 never learned RP $RPLH_ADDR (BSR/cand-RP path)"
		return 1
	fi

	print "3. ED2's membership reaches the RP it is directly attached to"
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 60 has_mrt r3 "$GROUP"; then
		ok "r3 has a ($GROUP) entry for its directly connected member"
	else
		fail "r3 never saw ED2's IGMP report, see $WORKDIR/r3.log"
		kill "$receiver" 2>/dev/null || true
		return 1
	fi

	print "4. Multicast reaches the receiver hanging off the RP itself"
	run_stream_and_sample
	if [ "$replies" -ge "$MIN_RECEIVED" ]; then
		ok "ED1 -> $GROUP -> ED2, $replies of $STREAM_PKTS packets delivered and answered"
	else
		fail "only $replies of $STREAM_PKTS packets reached ED2 ($RCV_ADDR), want >= $MIN_RECEIVED"
	fi

	print "5. The RP builds (S,G) state for the remote source and leaves the register vif"
	if [ -n "$sg_seen" ]; then
		ok "r3 created an ($SRC_ADDR,$GROUP) entry while the stream was running"
	else
		fail "r3 never created an ($SRC_ADDR,$GROUP) entry, it only ever had the (*,G)"
	fi
	if [ -n "$sg_native" ]; then
		ok "r3 ($SRC_ADDR,$GROUP) incoming interface became vif $sg_native, not the register vif"
	else
		fail "r3 ($SRC_ADDR,$GROUP) stayed on the register vif (vif 0), the RP never switched to the SPT"
	fi

	# The RP is supposed to pull the source onto a native path and
	# register-stop R1 within the first packets.  One register per data
	# packet is the encapsulate-forever state of the issue.
	print "6. The RP stops the registers instead of decapsulating every packet"
	if [ "$regs" -lt "$MAX_REGISTERS" ]; then
		ok "r3 decapsulated $regs registers for $STREAM_PKTS packets"
	else
		fail "r3 decapsulated $regs registers for $STREAM_PKTS packets, it never register-stopped r1"
	fi

	print "7. The kernel MFC on the RP agrees with pimd"
	if has_mfc r3 "$SRC_ADDR"; then
		ok "r3 kernel has an MFC entry for $SRC_ADDR"
	else
		fail "r3 kernel MFC has nothing for $SRC_ADDR, pimd never pushed the route down"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in $ROUTERS; do
		dprint "--- $r: pimctl show mrt detail ---"
		pimctl "$r" show mrt detail 2>&1 | tail -40 || true
	done
	dprint "--- r3: $MFC_SHOW_CMD ---"
	mfc_show r3 2>&1 || true
	dprint "--- registers decapsulated by r3, total: $(registers_seen) ---"
	return 1
}

# rp-offpath: run the ED1 -> ED2 stream and watch the last hop router while
# it is in flight.  Sets: replies, sg_first, sg_last.
#
# sg_first is the incoming interface R3's (S,G) is created with, sg_last the
# one it ends the stream on.  The two differ here and nowhere else: the
# (*,G) arrives over R2 and the source sits behind the direct link, so a
# router that switches to the shortest path tree has to move the incoming
# interface from one to the other.  Sampling has to happen while the stream
# runs, because killing the receiver expires the membership and the (S,G)
# with it.
run_stream_and_sample_offpath() {
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$STREAM_PKTS" -w 90 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 &
	sender=$!

	sg_first=
	sg_last=
	direct=$(vif_index r3 "$OFFPATH_R3_IF")
	deadline=$(($(date +%s) + STREAM_PKTS + 30))
	while [ "$(date +%s)" -lt "$deadline" ]; do
		iif=$(route_iif r3 "$SRC_ADDR" "$GROUP")
		if [ -n "$iif" ]; then
			[ -n "$sg_first" ] || sg_first=$iif
			sg_last=$iif
			[ "$iif" = "$direct" ] && break
		fi
		sleep 1
	done

	wait "$sender" 2>/dev/null || true
	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true

	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
}

# Issue #211: the RP is one hop off the path the traffic takes, and every
# router in the domain is adjacent to it.  The last hop router is therefore
# directly connected to the BSR, which is the case a BSD pimd used to get
# wrong: its RPF lookup went to the kernel even for an address on one of its
# own subnets, the route to a connected subnet has no gateway, and both
# receive_pim_bootstrap() and set_incoming() read a missing gateway as "no
# RPF neighbour" and give up.  The router next to the RP then never learned
# the RP set at all, so it could not send the (*,G) Join its receiver needed
# and no traffic ever arrived, which is what the issue reports.
check_rp_offpath() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. PIM neighbors are discovered, including over the direct link"
	if wait_for 60 has_neighbor r1 10.0.12.2; then
		ok "r1 sees r2 (10.0.12.2)"
	else
		fail "r1 never saw r2, PIM hello is not crossing ${EP}112"
	fi
	if wait_for 60 has_neighbor r3 "$OFFPATH_RP_ADDR"; then
		ok "r3 sees r2 ($OFFPATH_RP_ADDR)"
	else
		fail "r3 never saw r2, PIM hello is not crossing ${EP}123"
	fi
	if wait_for 60 has_neighbor r1 "$OFFPATH_R3_ADDR"; then
		ok "r1 sees r3 over the direct link ($OFFPATH_R3_ADDR)"
	else
		fail "r1 never saw r3 on ${EP}113, the triangle has no short edge"
	fi
	if wait_for 60 has_neighbor r3 "$OFFPATH_R1_ADDR"; then
		ok "r3 sees r1 over the direct link ($OFFPATH_R1_ADDR)"
	else
		fail "r3 never saw r1 on ${EP}113"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	# R3 is the router the issue is about: the BSR is an address on a
	# subnet it is directly connected to, and it is the only router here
	# for which that is true.  R1 reaches the BSR through R2, so it
	# learns the RP set over an ordinary routed path either way.
	print "3. The RP set reaches the router directly connected to the BSR"
	if wait_for 90 has_rp r1 "$OFFPATH_RP_ADDR"; then
		ok "r1 learned RP $OFFPATH_RP_ADDR"
	else
		fail "r1 never learned RP $OFFPATH_RP_ADDR (BSR/cand-RP path)"
	fi
	if wait_for 90 has_rp r3 "$OFFPATH_RP_ADDR"; then
		ok "r3 learned RP $OFFPATH_RP_ADDR from the BSR on its own subnet"
	else
		fail "r3 never learned RP $OFFPATH_RP_ADDR: every Bootstrap from the directly connected BSR is dropped, see $WORKDIR/r3.log"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "4. ED2's membership gives the last hop router a group entry"
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 60 has_mrt r3 "$GROUP"; then
		ok "r3 has a ($GROUP) entry for its directly connected member"
	else
		fail "r3 never created a ($GROUP) entry, it has no RP to join towards"
		kill "$receiver" 2>/dev/null || true
		return 1
	fi

	print "5. Multicast is forwarded from ED1 to ED2 with the RP off the path"
	run_stream_and_sample_offpath
	if [ "$replies" -ge "$MIN_RECEIVED" ]; then
		ok "ED1 -> $GROUP -> ED2, $replies of $STREAM_PKTS packets delivered and answered"
	else
		fail "only $replies of $STREAM_PKTS packets reached ED2, want >= $MIN_RECEIVED"
	fi

	# The shared tree comes in over R2 and the source is out the direct
	# link, so the switch has to move the incoming interface between two
	# ordinary interfaces.  In the chain scenarios both are the same one
	# and the switch cannot be seen from the outside at all.
	print "6. The last hop router switches to the shortest path tree"
	direct=$(vif_index r3 "$OFFPATH_R3_IF")
	rpt=$(vif_index r3 ${EP}123b)
	if [ -n "$sg_first" ]; then
		ok "r3 created an ($SRC_ADDR,$GROUP) entry while the stream was running"
	else
		fail "r3 never created an ($SRC_ADDR,$GROUP) entry, it stayed on the (*,G)"
	fi
	if [ "$sg_last" = "$direct" ]; then
		ok "r3 ($SRC_ADDR,$GROUP) pulled its incoming interface onto $OFFPATH_R3_IF (vif $direct)"
	else
		fail "r3 ($SRC_ADDR,$GROUP) incoming interface is vif ${sg_last:-none}, want vif $direct ($OFFPATH_R3_IF), the RPT interface is vif $rpt"
	fi

	print "7. The kernel MFC on the last hop router agrees with pimd"
	if has_mfc r3 "$SRC_ADDR"; then
		ok "r3 kernel has an MFC entry for $SRC_ADDR"
	else
		fail "r3 kernel MFC has nothing for $SRC_ADDR, pimd never pushed the route down"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in $ROUTERS; do
		dprint "--- $r: pimctl show rp ---"
		pimctl "$r" show rp 2>&1 || true
		dprint "--- $r: pimctl show mrt detail ---"
		pimctl "$r" show mrt detail 2>&1 | tail -30 || true
	done
	return 1
}

# The gif-tunnel variant of check_rp_lasthop.  Same RP-is-also-last-hop
# question, but now everything PIM crosses a point-to-point tunnel and R2
# is not a PIM router at all, so the two ends have to find each other with
# nothing but unicast in between.  What is genuinely new here is the
# interface type: config_vifs_from_kernel() takes the IFF_POINTOPOINT
# branch, so uv_rmt_addr comes from ifa_dstaddr and the vif is flagged
# VIFF_POINT_TO_POINT | VIFF_REXMIT_PRUNES, and the hellos, the DR
# election and the RPF answers all have to work off that.
check_gif_tunnel() {
	print "1. pimd is alive on both tunnel endpoints"
	for r in $(pim_routers); do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. pimd accepted the point-to-point tunnel as a vif"
	for r in $(pim_routers); do
		if has_iface "$r" "$GIF_IF"; then
			ok "$r has $GIF_IF in its interface table"
		else
			fail "$r never built a vif for $GIF_IF, see $WORKDIR/$r.log for an 'Ignoring' line"
		fi
	done
	if took_p2p_branch r1 "$GIF_R1" "$GIF_R3" &&
	   took_p2p_branch r3 "$GIF_R3" "$GIF_R1"; then
		ok "both ends installed $GIF_IF through the IFF_POINTOPOINT branch"
	else
		fail "$GIF_IF came up as an ordinary subnet vif, this scenario is not exercising the tunnel path"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "3. PIM adjacency comes up across the tunnel"
	if wait_for 90 has_neighbor r1 "$GIF_R3"; then
		ok "r1 sees r3 ($GIF_R3) over $GIF_IF"
	else
		fail "r1 never saw r3 over the tunnel, hellos are not crossing $GIF_IF"
	fi
	if wait_for 90 has_neighbor r3 "$GIF_R1"; then
		ok "r3 sees r1 ($GIF_R1) over $GIF_IF"
	else
		fail "r3 never saw r1 over the tunnel"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "4. R3 is the RP, and R1 learns it through the tunnel"
	if wait_for 90 has_rp r3 "$RPLH_ADDR"; then
		ok "r3 elected itself RP ($RPLH_ADDR)"
	else
		fail "r3 never became RP, see $WORKDIR/r3.log"
		return 1
	fi
	if wait_for 90 has_rp r1 "$RPLH_ADDR"; then
		ok "r1 learned RP $RPLH_ADDR over the tunnel"
	else
		fail "r1 never learned RP $RPLH_ADDR, bootstrap is not crossing $GIF_IF"
		return 1
	fi

	print "5. ED2's membership reaches the RP it is directly attached to"
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 60 has_mrt r3 "$GROUP"; then
		ok "r3 has a ($GROUP) entry for its directly connected member"
	else
		fail "r3 never saw ED2's IGMP report, see $WORKDIR/r3.log"
		kill "$receiver" 2>/dev/null || true
		return 1
	fi

	print "6. Multicast crosses the tunnel to the receiver on the RP"
	run_stream_and_sample
	if [ "$replies" -ge "$MIN_RECEIVED" ]; then
		ok "ED1 -> $GROUP -> ED2 over $GIF_IF, $replies of $STREAM_PKTS delivered and answered"
	else
		fail "only $replies of $STREAM_PKTS packets reached ED2 ($RCV_ADDR) through the tunnel"
	fi

	print "7. The RP builds (S,G) state and leaves the register vif"
	if [ -n "$sg_seen" ]; then
		ok "r3 created an ($SRC_ADDR,$GROUP) entry while the stream was running"
	else
		fail "r3 never created an ($SRC_ADDR,$GROUP) entry, it only ever had the (*,G)"
	fi
	if [ -n "$sg_native" ]; then
		ok "r3 ($SRC_ADDR,$GROUP) incoming interface became vif $sg_native, not the register vif"
	else
		fail "r3 ($SRC_ADDR,$GROUP) stayed on the register vif (vif 0), the RP never switched to the SPT"
	fi

	print "8. The RP stops the registers instead of decapsulating every packet"
	if [ "$regs" -lt "$MAX_REGISTERS" ]; then
		ok "r3 decapsulated $regs registers for $STREAM_PKTS packets"
	else
		fail "r3 decapsulated $regs registers for $STREAM_PKTS packets, it never register-stopped r1"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	# show compat prints the vif table with its Subnet column, which is
	# the format the issue reporters pasted and the place a mishandled
	# point-to-point netmask would show up
	for r in $(pim_routers); do
		dprint "--- $r: pimctl show compat detail ---"
		pimctl "$r" show compat detail 2>&1 | head -30 || true
		dprint "--- $r: $GIF_IF ---"
		box_if_show "$r" "$GIF_IF" 2>&1 | head -4 || true
	done
	dprint "--- registers decapsulated by r3, total: $(registers_seen) ---"
	return 1
}

# gif-tunnel again, but with the RP configured statically on both ends,
# the way every pimd.conf quoted in #243 is written.  See write_configs()
# for why that is a different code path and not just a different way of
# reaching the same state: my_cand_rp_address stays 0.0.0.0 on a static
# RP, so the router that *is* the RP answers "no" to every internal test
# of whether it is.
check_gif_staticrp() {
	print "1. pimd is alive on both tunnel endpoints"
	for r in $(pim_routers); do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. Both ends took the static RP from pimd.conf"
	for r in $(pim_routers); do
		if wait_for 30 has_static_rp "$r" "$RPLH_ADDR"; then
			ok "$r has $RPLH_ADDR as a static RP for $GROUP"
		else
			fail "$r did not accept 'rp-address $RPLH_ADDR 224.0.0.0/16', see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "3. PIM adjacency comes up across the tunnel"
	if wait_for 90 has_neighbor r1 "$GIF_R3"; then
		ok "r1 sees r3 ($GIF_R3) over $GIF_IF"
	else
		fail "r1 never saw r3 over the tunnel"
	fi
	if wait_for 90 has_neighbor r3 "$GIF_R1"; then
		ok "r3 sees r1 ($GIF_R1) over $GIF_IF"
	else
		fail "r3 never saw r1 over the tunnel"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "4. ED2's membership reaches the RP it is directly attached to"
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 60 has_mrt r3 "$GROUP"; then
		ok "r3 has a ($GROUP) entry for its directly connected member"
	else
		fail "r3 never saw ED2's IGMP report, see $WORKDIR/r3.log"
		kill "$receiver" 2>/dev/null || true
		return 1
	fi

	# A static RP is known from the moment pimd parses pimd.conf, so
	# this scenario reaches its first four assertions in seconds, where
	# the elected-RP one spends up to 90s waiting for bootstrap.  Left
	# alone, the stream would then start much earlier in the lab's life
	# and measure a slice of PIM convergence that gif-tunnel has already
	# sat through, and the two delivery counts would not be comparable.
	print "5. Letting PIM settle so the delivery count means the same thing as gif-tunnel's"
	sleep "$SETTLE"

	print "6. Multicast crosses the tunnel to the receiver on the RP"
	run_stream_and_sample
	if [ "$replies" -ge "$MIN_RECEIVED" ]; then
		ok "ED1 -> $GROUP -> ED2 over $GIF_IF, $replies of $STREAM_PKTS delivered and answered"
	else
		fail "only $replies of $STREAM_PKTS packets reached ED2 ($RCV_ADDR) through the tunnel"
	fi

	print "7. The RP builds (S,G) state and leaves the register vif"
	if [ -n "$sg_seen" ]; then
		ok "r3 created an ($SRC_ADDR,$GROUP) entry while the stream was running"
	else
		fail "r3 never created an ($SRC_ADDR,$GROUP) entry, it only ever had the (*,G)"
	fi
	if [ -n "$sg_native" ]; then
		ok "r3 ($SRC_ADDR,$GROUP) incoming interface became vif $sg_native, not the register vif"
	else
		fail "r3 ($SRC_ADDR,$GROUP) stayed on the register vif (vif 0), the RP never switched to the SPT"
	fi

	print "8. The RP stops the registers instead of decapsulating every packet"
	if [ "$regs" -lt "$MAX_REGISTERS" ]; then
		ok "r3 decapsulated $regs registers for $STREAM_PKTS packets"
	else
		fail "r3 decapsulated $regs registers for $STREAM_PKTS packets, it never register-stopped r1"
	fi

	# The assertion this scenario exists for.  R3 is the RP for $GROUP
	# and the DR for $RCV_ADDR's subnet, so it must never put the
	# register vif in that source's oif list: there is nobody to
	# register to but itself.  process_cache_miss() decides that with
	# "group->rpaddr != my_cand_rp_address" (src/route.c), which a
	# static RP can never satisfy.
	print "9. The RP does not encapsulate its own directly connected source to itself"
	if [ -z "$selfreg" ]; then
		ok "r3 kept the register vif out of the oifs for $RCV_ADDR"
	else
		fail "r3 put the register vif in the oifs for its own source $RCV_ADDR, it is registering to itself"
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in $(pim_routers); do
		dprint "--- $r: pimctl show compat detail ---"
		pimctl "$r" show compat detail 2>&1 | head -30 || true
	done
	dprint "--- r3: pimctl show mrt detail ---"
	pimctl r3 show mrt detail 2>&1 | head -40 || true
	dprint "--- registers decapsulated by r3, total: $(registers_seen) ---"
	return 1
}

# The shared segment scenario.  Everything up to assertion 5 is the rpt
# scenario with the right hand links rebuilt as bridges; from 6 on it is the
# part no point-to-point link can reach, where three routers have to agree
# on who speaks for a LAN they all sit on.
check_shared_lan() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. Every router on a bridged segment sees every other one"
	for pair in "r2 10.0.23.3" "r2 10.0.23.4" \
		    "r3 10.0.23.2" "r3 10.0.23.4" \
		    "r4 10.0.23.2" "r4 10.0.23.3"; do
		# shellcheck disable=SC2086
		set -- $pair
		if wait_for 60 has_neighbor "$1" "$2"; then
			ok "$1 sees $2 on the upstream segment"
		else
			fail "$1 never saw $2, PIM hello is not crossing $BR_UPSTREAM"
		fi
	done
	for pair in "r3 $SL_DR_ADDR" "r3 $SL_QUERIER_ADDR" \
		    "r4 $SL_R3_ADDR" "r4 $SL_QUERIER_ADDR" \
		    "r5 $SL_R3_ADDR" "r5 $SL_DR_ADDR"; do
		# shellcheck disable=SC2086
		set -- $pair
		if wait_for 60 has_neighbor "$1" "$2"; then
			ok "$1 sees $2 on the shared LAN"
		else
			fail "$1 never saw $2, PIM hello is not crossing $BR_RECEIVER"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "3. The DR election on the shared LAN takes the highest address"
	dr3=$(iface_dr r3 "$SL_R3_IF")
	dr4=$(iface_dr r4 "$SL_R4_IF")
	dr5=$(iface_dr r5 ${EP}503b)
	if [ "$dr3" = "$SL_DR_ADDR" ] && [ "$dr4" = "$SL_DR_ADDR" ] &&
	   [ "$dr5" = "$SL_DR_ADDR" ]; then
		ok "r3, r4 and r5 all call $SL_DR_ADDR (r4) the DR"
	else
		fail "DR disagreement: r3 '$dr3', r4 '$dr4', r5 '$dr5', all should say $SL_DR_ADDR"
	fi

	# Two elections over the same wire, deliberately won by different
	# routers: PIM takes the highest address, IGMP the lowest.
	print "4. The IGMP querier election takes the lowest, i.e. another router"
	if wait_for 90 queriers_settled; then
		ok "r5 ($SL_QUERIER_ADDR) is the querier, r3 and r4 agree"
	else
		q3=$(iface_querier r3 "$SL_R3_IF")
		q4=$(iface_querier r4 "$SL_R4_IF")
		q5=$(iface_querier r5 ${EP}503b)
		fail "querier disagreement: r5 '$q5' (want Local), r3 '$q3', r4 '$q4' (want $SL_QUERIER_ADDR)"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "5. The RP set is distributed by the bootstrap router"
	for r in $ROUTERS; do
		if wait_for 90 has_rp "$r" "$RP_ADDR"; then
			ok "$r learned RP $RP_ADDR"
		else
			fail "$r never learned RP $RP_ADDR (BSR/cand-RP path)"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	# ED3 joins first, and on its own port, so this window has exactly one
	# reason for anyone to forward onto the LAN: an IGMP report.  pimd
	# gives it to the DR alone.  add_leaf() (src/route.c) looks the group
	# up with DONT_CREATE unless VIFF_DR is set, on the grounds that "if a
	# non-DR last-hop router has not received a PIM Join, it should not
	# create a PIM state, otherwise later this state may incorrectly
	# trigger PIM joins" - a deliberate deviation, and the reason this
	# scenario needs a downstream router to get its second forwarder.
	print "6. An IGMP report on the LAN is taken by the DR and by nobody else"
	box_run ed3 "$MPING" -r -i ${EP}603b -p "$SL_JOIN_PORT" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/joiner.log" 2>&1 &
	joiner=$!
	if wait_for 60 has_mrt r4 "$GROUP"; then
		ok "r4, the DR, created a ($GROUP) entry for ED3's report"
	else
		fail "r4 never saw ED3's IGMP report, see $WORKDIR/r4.log"
		kill "$joiner" 2>/dev/null || true
		return 1
	fi
	if has_mrt r3 "$GROUP"; then
		fail "r3 is not the DR but created a ($GROUP) entry from the report alone"
	else
		ok "r3, not the DR, created nothing from the same report"
	fi

	# The other way onto a LAN: R5 wants the group for ED2 and its RPF
	# neighbour is R3, so its Join names R3, and R3 is the one router on
	# the LAN that may act on it.
	print "7. A downstream Join gives the non-DR an oif on the same LAN"
	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 90 joined_on r3 "$SL_R3_IF" "$GROUP"; then
		ok "r3 joined $GROUP towards the LAN on r5's behalf"
	else
		fail "r3 never took r5's Join, see $WORKDIR/r3.log"
		kill "$joiner" "$receiver" 2>/dev/null || true
		return 1
	fi

	# R5 is on the same LAN, hears the same report -- it is the IGMP
	# querier there -- and has a (*,G) of its own, being the router ED2
	# sits behind.  What it is not is the DR, and RFC 7761 sec. 4.1.5
	# keeps a local member out of the outgoing interfaces of anyone else:
	# pim_include(*,G) counts interface I only where I_am_DR(I).  Without
	# that gate R5 forwards onto a LAN that already has a forwarder, and
	# the receivers on it get every packet twice until an assert election
	# settles it -- an election only a data packet on the wrong interface
	# can even start.
	if [ "$(iface_dr r5 ${EP}503b)" = "$SL_DR_ADDR" ]; then
		if map_isset r5 ${EP}503b "$(route_map r5 ANY "$GROUP" Outgoing)"; then
			fail "r5 is not the DR on the LAN but forwards $GROUP onto it"
		else
			ok "r5, not the DR, keeps the LAN out of its oifs"
		fi
	else
		dprint "r5 reads the DR as $(iface_dr r5 ${EP}503b), not $SL_DR_ADDR, skipping"
	fi

	print "8. Multicast reaches the receiver at the far end of the tree"
	run_stream_and_sample_shared
	kill "$joiner" 2>/dev/null || true
	if [ "$replies" -ge "$MIN_RECEIVED" ]; then
		ok "ED1 -> $GROUP -> ED2, $replies replies for $STREAM_PKTS packets"
	else
		fail "only $replies replies for $STREAM_PKTS packets, want >= $MIN_RECEIVED"
	fi

	# The assertion these scenarios exist for.  Both routers put the group
	# on the LAN, so each of them receives the other's copy on an
	# interface that is not its own iif, the kernel raises IGMPMSG_WRONGVIF
	# for it (ip_mroute.c, with the assert upcalls pimd turns on through
	# MRT_PIM), and the loser of the election that follows has to take its
	# oif back out.  The election itself is not in the default debug set;
	# "pimctl -u $WORKDIR/r3.sock debug asserts" on a running lab logs the
	# Send/Received PIM ASSERT pair that produced this state.
	#
	# Who should win differs between the two scenarios, and that is the
	# reason shared-lan-spt exists.  RFC 7761 4.6.1 compares assert
	# metrics field by field, rpt_bit_flag first, and my_assert_metric()
	# (p.93) only returns the SPT metric, with that flag clear, when
	# CouldAssert(S,G,I) holds - which requires SPTbit(S,G) == TRUE
	# (p.75).  A router forwarding a group it only has (*,G) state for
	# must therefore assert with the flag set, and lose to one that has
	# (S,G) state, whatever the addresses are.
	#
	# In shared-lan neither contender has (S,G) state of its own, both
	# assert as RPT forwarders, and the address decides: R4 wins.
	#
	# In shared-lan-spt R5's switch gives R3 real (S,G) state while R4
	# still has only ED3's (*,G) leaf, so R3 must win with the *lower*
	# address.  pimd did not do that before 4cb79f1: send_pim_assert() and
	# receive_pim_assert() (src/pim_proto.c) took the RPT bit straight
	# from MRTF_RP on whichever entry they were forwarding off, and
	# MRTF_RP is only ever set from an explicit
	# (S,G,rpt) Join/Prune or when an entry's iif changes to point at the
	# RP (src/route.c, src/mrt.c) - never on the (S,G) a cache miss builds
	# under a (*,G).  So R4 asserted as though it were on the shortest
	# path tree too, both metrics tied, and the address handed it a win
	# the spec does not.  One my_assert_metric() derives the bit from
	# MRTF_SPT for both paths now; the xfail() below stays as a tripwire.
	if [ "$SCENARIO" = shared-lan-spt ]; then
		print "9. The assert winner is the router with the better tree"
		if [ -z "$sg3" ]; then
			fail "r3 never got (S,G) state from r5, the election below cannot be read; r5 never switched, see $WORKDIR/r5.log"
		elif [ -n "$fwd3" ] && [ -z "$fwd4" ]; then
			ok "r3 won with the lower address, off its (S,G): pimd sets the RPT bit as RFC 7761 4.6.1 requires"
		elif [ -n "$fwd4" ] && [ -z "$fwd3" ]; then
			xfail "r4 ($SL_DR_ADDR) won on the address; per RFC 7761 4.6.1 r3 has (S,G) state and r4 only (*,G), so r4 must assert with the RPT bit set and lose"
		elif [ -n "$fwd3" ] && [ -n "$fwd4" ]; then
			fail "both r3 and r4 still forward $GROUP onto the LAN, no assert settled it"
		else
			fail "neither r3 nor r4 forwards $GROUP onto the LAN"
		fi
	else
		print "9. The duplicate on the LAN is settled by a PIM assert"
		if [ -n "$fwd4" ] && [ -z "$fwd3" ]; then
			ok "only r4 ($SL_DR_ADDR) still forwards $GROUP onto the LAN, it has the higher address"
		elif [ -n "$fwd3" ] && [ -n "$fwd4" ]; then
			fail "both r3 and r4 still forward $GROUP onto the LAN, no assert settled it"
		elif [ -n "$fwd3" ]; then
			fail "r3 ($SL_R3_ADDR) won the assert, r4 has the higher address and should have"
		else
			fail "neither r3 nor r4 forwards $GROUP onto the LAN"
		fi
		if [ -n "$ast3" ] && [ -z "$ast4" ]; then
			ok "r3 has the LAN in its asserted oifs, r4 does not"
		else
			fail "asserted oifs are wrong: r3 '${ast3:-none}', r4 '${ast4:-none}'"
		fi
	fi

	print "10. Only the DR registers the source that sits on the shared LAN"
	if [ -z "$reg3" ]; then
		ok "r3 kept the register vif out of the oifs for $SL_ED3_ADDR"
	else
		fail "r3 is not the DR for $SL_ED3_ADDR but registered it anyway"
	fi

	# Whoever won it, the winner is the one that has to hold the kernel
	# state: asserting is only half of it, the forwarding has to follow.
	winner=r4
	[ -n "$fwd3" ] && winner=r3
	print "11. The kernel MFC on the assert winner agrees with pimd"
	if has_mfc "$winner" "$GROUP"; then
		ok "$winner kernel has an MFC entry for $GROUP"
	else
		fail "$winner won the assert but its kernel MFC is empty, pimd never pushed the route down"
	fi

	if [ "$SCENARIO" = shared-lan ]; then
		check_assert_metric
	fi

	echo
	if [ "$FAILED" -eq 0 ]; then
		if [ "$XFAILED" -gt 0 ]; then
			print "RESULT: PASS ($XFAILED known deviation(s), see above)"
		else
			print "RESULT: PASS"
		fi
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	for r in r3 r4 r5; do
		dprint "--- $r: pimctl show interface ---"
		pimctl "$r" show interface 2>&1 || true
		dprint "--- $r: pimctl show igmp ---"
		pimctl "$r" show igmp 2>&1 || true
		dprint "--- $r: pimctl show mrt detail ---"
		pimctl "$r" show mrt detail 2>&1 | head -40 || true
		dprint "--- $r: $MFC_SHOW_CMD ---"
		mfc_show "$r" 2>&1 || true
	done
	return 1
}

stop() {
	for r in $SHARED_ROUTERS; do
		[ -f "$WORKDIR/$r.pid" ] && \
			${SUDO} pkill -F "$WORKDIR/$r.pid" 2>/dev/null || true
	done
	# Every other slot runs the same three binaries out of the same
	# tree, so the work directory is what tells this lab's processes
	# from theirs: pimd is named by the control socket it was given,
	# mping and msend by the copy that was built for this slot.
	${SUDO} pkill -f -- "-u $WORKDIR/" 2>/dev/null || true
	${SUDO} pkill -f "$MPING" 2>/dev/null || true
	${SUDO} pkill -f "$MSEND" 2>/dev/null || true

	for box in $ALL_BOXES; do
		destroy_box "$box"
	done

	destroy_links

	restore_mcast_loop
	${SUDO} rm -rf "$WORKDIR"
}

# SIGTERM every pimd this lab started, and wait for them to go.  What a
# sanitizer has to say at exit -- a leak check above all, which is the whole
# of what LeakSanitizer does -- is said when the daemon exits, so for those
# reports to exist at all the daemons have to be stopped before they are
# looked for.  stop() does that too, but it takes the work directory with
# it, reports and all.
stop_pimd() {
	for r in $SHARED_ROUTERS; do
		[ -f "$WORKDIR/$r.pid" ] || continue
		${SUDO} pkill -F "$WORKDIR/$r.pid" 2>/dev/null || true
	done

	for r in $SHARED_ROUTERS; do
		[ -f "$WORKDIR/$r.pid" ] || continue
		wait_for 15 pimd_is_down "$r" || true
	done
}

# What the sanitizers wrote while the scenario ran, if this is a SANITIZE
# run.  A scenario whose pimd hit undefined behaviour did not pass, whatever
# its assertions made of what came out on the wire, so this is asked after
# every one of them and has a verdict of its own -- the RESULT above is the
# assertions' answer and knows nothing about it.
check_sanitizer() {
	[ "$SANITIZE" = yes ] || return 0

	echo
	print "Sanitizer reports"

	# shellcheck disable=SC2046
	set -- $(${SUDO} find "$SAN_DIR" -type f 2>/dev/null | sort)
	if [ $# -eq 0 ]; then
		ok "no sanitizer report from any pimd in this scenario"
		return 0
	fi

	for f in "$@"; do
		dprint "--- ${f##*/} ---"
		${SUDO} sed -n 1,40p "$f" 2>/dev/null || true
	done

	print "RESULT: FAIL ($# sanitizer report(s), whatever the result above says)"
	return 1
}

# privsep: the daemon is two processes, and the one that parses the wire is
# not the one holding root.  On the default chain rather than on solo's
# single router, and that is the whole lesson of how this landed: a sandbox
# that forbids *sending* -- which is what Capsicum turned out to be, see
# priv_sandbox_enter() in src/privsep.c -- leaves a lone router looking
# perfectly healthy.  It comes up, answers pimctl, elects itself BSR and RP,
# builds its VIFs, and nothing it sends ever leaves the host.  "run solo"
# passed like that.  It takes a neighbour to notice, so the split is
# asserted here and then the whole protocol is run on top of it.
#
# The control is step 7: the same chain with r1 unseparated.  Without it
# every assertion above would pass just as well on a daemon that separated
# nothing, since "still forwards multicast" is what pimd did before any of
# this.
check_privsep() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if wait_for "$PIMD_START_WAIT" pimd_is_up "$r"; then
			ok "$r: pimd answers on its pimctl socket"
		else
			fail "$r: pimd not answering, see $WORKDIR/$r.log"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "2. It is two processes, and only one of them is root"
	ps_parent=$(${SUDO} cat "$WORKDIR/r1.pid" 2>/dev/null)
	if [ -n "$ps_parent" ] && [ "$(proc_user "$ps_parent")" = root ]; then
		ok "r1: the PID file names $ps_parent, and it runs as root"
	else
		fail "r1: the PID file names '$ps_parent', running as '$(proc_user "$ps_parent")', expected a root process"
		return 1
	fi

	ps_child=$(proc_children "$ps_parent" | head -1)
	ps_user=$(proc_user "$ps_child")
	if [ -n "$ps_child" ] && [ -n "$ps_user" ] && [ "$ps_user" != root ]; then
		ok "r1: it forked $ps_child, which runs as $ps_user and not as root"
	else
		fail "r1: the root process forked '$ps_child' running as '$ps_user', expected an unprivileged child"
		return 1
	fi

	# The PID file has to name the half a SIGHUP can act on.  Step 6 sends
	# one; this is what makes that meaningful rather than lucky.
	if [ "$ps_child" != "$ps_parent" ]; then
		ok "r1: the PID file names the privileged half, which is the one signals must reach"
	else
		fail "r1: the PID file names the unprivileged child, a SIGHUP would not reach the sockets"
	fi

	print "3. pimd says the same about itself, and names this system's sandbox"
	got=$(pimctl r1 show status | sed -n 's/^Privilege separation *: *//p')
	want="$ps_user, sandbox $SANDBOX_NAME, chroot "
	case $got in
	"$want"*)
		ok "r1: 'show status' reads '$got'" ;;
	*)
		fail "r1: 'show status' reads '$got', expected '$want<dir>'"
		return 1 ;;
	esac
	ps_root=${got##*, chroot }

	print "4. And the kernel agrees, which is the half pimd cannot fake"
	if [ "$SANDBOX_NAME" = none ]; then
		ok "no sandbox on this system, the uid drop asserted above stands on its own"
	elif proc_confined "$ps_child"; then
		ok "r1: the kernel holds $ps_child in a sandbox"
	else
		fail "r1: pimd claims a $SANDBOX_NAME sandbox that the kernel does not hold $ps_child in"
	fi

	# What the kernel resolves the child's "/" to, against what pimd says
	# it confined it to.  A chroot pimd claims and did not do, or did
	# somewhere other than where it says, is what this catches.
	ps_kroot=$(proc_root "$ps_child")
	if [ "$ps_root" = none ]; then
		if [ "$ps_kroot" = / ]; then
			ok "built --without-privsep-chroot, and the child is rooted at / as pimd says"
		else
			fail "r1: pimd claims no chroot and the kernel has $ps_child rooted at '$ps_kroot'"
		fi
	elif [ "$ps_kroot" = "$ps_root" ]; then
		ok "r1: the kernel has $ps_child rooted at $ps_kroot, with no path left for it to open"
	else
		fail "r1: pimd claims chroot $ps_root and the kernel has $ps_child rooted at '$ps_kroot'"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "5. The unprivileged half runs the whole protocol"
	if wait_for 60 has_neighbor r1 10.0.12.2; then
		ok "r1 sees r2 (10.0.12.2), so its Hellos leave the host and r2's arrive"
	else
		fail "r1 never saw r2, PIM hello is not crossing ${EP}112"
	fi
	if wait_for 90 has_rp r3 "$RP_ADDR"; then
		ok "r3 learned RP $RP_ADDR, three hops of BSR and Cand-RP-Adv"
	else
		fail "r3 never learned RP $RP_ADDR (BSR/cand-RP path)"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	privsep_stream "the separated chain" || return 1

	# Every "pimctl show" has the privileged half open a scratch file and
	# pass the descriptor over, which is the one path in normal running
	# where a descriptor crosses and could be left behind.  A leak there
	# is not a memory error and no sanitizer reports it: the count is the
	# only thing that does.  The audit of e0612d3 found the version of it
	# that a compromised child could drive; this is the tripwire for the
	# ordinary one, which is what a later edit is likely to reintroduce.
	print "6. Passing descriptors does not leave them behind in the parent"
	ps_fds_before=$(proc_nfds "$ps_parent")
	ps_i=0
	while [ "$ps_i" -lt 40 ]; do
		pimctl r1 show mrt >/dev/null 2>&1 || true
		pimctl r1 show igmp groups >/dev/null 2>&1 || true
		ps_i=$((ps_i + 1))
	done
	ps_fds_after=$(proc_nfds "$ps_parent")

	if [ -z "$ps_fds_before" ] || [ -z "$ps_fds_after" ]; then
		fail "r1: could not count the descriptors of $ps_parent"
	elif [ "$ps_fds_after" -le "$ps_fds_before" ]; then
		ok "r1: the parent holds $ps_fds_after descriptors after 80 pimctl commands, $ps_fds_before before"
	else
		fail "r1: the parent went from $ps_fds_before descriptors to $ps_fds_after over 80 pimctl commands"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "7. A SIGHUP to the PID file rebuilds every VIF through the parent"
	vifs_before=$(pimctl r1 -t show interface 2>/dev/null | grep -c Up)
	${SUDO} kill -HUP "$ps_parent" 2>/dev/null || \
		fail "r1: could not signal $ps_parent"
	if wait_for 30 pimd_is_up r1; then
		ok "r1: pimd answers again after the SIGHUP"
	else
		fail "r1: pimd stopped answering after a SIGHUP to the parent, see $WORKDIR/r1.log"
		return 1
	fi

	# Every descriptor the child had is gone and a new set has come from
	# the parent: sockets, the pimd.conf it re-read, and the pimctl socket
	# the parent bound again.  The VIF count is the cheapest thing that
	# says all of that worked.
	vifs_after=$(pimctl r1 -t show interface 2>/dev/null | grep -c Up)
	if [ "$vifs_after" -gt 0 ] && [ "$vifs_after" = "$vifs_before" ]; then
		ok "r1 has its $vifs_after interfaces up again, on descriptors the parent handed back"
	else
		fail "r1 had $vifs_before interfaces up and has $vifs_after after the reload"
	fi

	if [ "$ps_parent" = "$(${SUDO} cat "$WORKDIR/r1.pid" 2>/dev/null)" ]; then
		ok "r1: and the PID file still names $ps_parent, touched by the privileged half"
	else
		fail "r1: the PID file names '$(${SUDO} cat "$WORKDIR/r1.pid" 2>/dev/null)' after the reload, was $ps_parent"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	if wait_for 90 has_neighbor r1 10.0.12.2; then
		ok "r1 found r2 again, so the new PIM socket sends and receives"
	else
		fail "r1 never saw r2 again after the reload"
		return 1
	fi
	privsep_stream "the reloaded chain" || return 1

	print "8. Control: --no-privsep is one root process, and forwards just as well"
	PIMD_ARGS="--no-privsep"
	restart_pimd r1
	if wait_for "$PIMD_START_WAIT" pimd_is_up r1; then
		ok "r1: pimd answers with --no-privsep"
	else
		fail "r1: pimd did not come up with --no-privsep, see $WORKDIR/r1.log"
		PIMD_ARGS=
		return 1
	fi

	ns_parent=$(${SUDO} cat "$WORKDIR/r1.pid" 2>/dev/null)
	ns_kids=$(proc_children "$ns_parent" | wc -l | tr -d " ")
	if [ "$(proc_user "$ns_parent")" = root ] && [ "$ns_kids" -eq 0 ]; then
		ok "r1 is a single root process again, $ns_parent with no children"
	else
		fail "r1 with --no-privsep runs as '$(proc_user "$ns_parent")' with $ns_kids child process(es), expected root and none"
	fi

	got=$(pimctl r1 show status | sed -n 's/^Privilege separation *: *//p')
	if [ "$got" = "none, running as root" ]; then
		ok "r1: 'show status' reads '$got', so the line above was not a constant"
	else
		fail "r1: 'show status' reads '$got' with --no-privsep, expected 'none, running as root'"
	fi

	if wait_for 90 has_neighbor r1 10.0.12.2 && wait_for 90 has_rp r1 "$RP_ADDR"; then
		ok "r1 rejoined the chain unseparated, neighbour and RP set back"
	else
		fail "r1 never rebuilt its adjacency with --no-privsep, the control says nothing"
		PIMD_ARGS=
		return 1
	fi
	privsep_stream "the unseparated chain"
	PIMD_ARGS=

	result || {
		dprint "--- r1: pimctl show status ---"
		pimctl r1 show status 2>&1 | tail -30 || true
		return 1
	}
}

# ED1 -> $GROUP -> ED2 across the three routers, named by what is being
# asked of it.  Three of the steps above end in this: the whole point of
# separating the daemon is that none of it changes.
privsep_stream() {
	ps_what=$1

	box_run ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 90 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	ps_receiver=$!
	sleep 2
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c 40 -w 60 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 || true
	kill "$ps_receiver" 2>/dev/null || true
	wait "$ps_receiver" 2>/dev/null || true

	ps_replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	ps_replies=${ps_replies:-0}
	if [ "$ps_replies" -ge "$MIN_REPLIES" ]; then
		ok "ED1 -> $GROUP -> ED2 over $ps_what, $ps_replies replies"
		return 0
	fi

	fail "only $ps_replies replies over $ps_what, want >= $MIN_REPLIES, see $WORKDIR/sender.log"
	return 1
}

# solo: every role on one router.  It is the one shape the rest of this
# file cannot build -- every other scenario has at least two PIM routers --
# and what it reaches is the router that is the DR of a source, the RP of
# the group that source sends to, the BSR that elected it, and the last hop
# router of a receiver on its other LAN, all at once.  A DR that is its own
# RP has nothing to register to and must forward the source down the shared
# tree itself, which process_cache_miss() (src/route.c) decides by comparing
# the group's RP with its own candidacy.
check_solo() {
	print "1. pimd is alive on the only router"
	if wait_for "$PIMD_START_WAIT" pimd_is_up r1; then
		ok "r1: pimd answers on its pimctl socket"
	else
		fail "r1: pimd not answering, see $WORKDIR/r1.log"
		return 1
	fi

	print "2. It elected itself, both as bootstrap router and as RP"
	if wait_for 60 elected_bsr_is r1 "$SOLO_RP_ADDR"; then
		ok "r1 is the BSR at $SOLO_RP_ADDR, having nobody to lose to"
	else
		fail "r1 reads its BSR as '$(elected_bsr r1)', expected $SOLO_RP_ADDR"
	fi
	if wait_for 60 has_rp r1 "$SOLO_RP_ADDR"; then
		ok "r1 learned the RP it advertises itself, $SOLO_RP_ADDR"
	else
		fail "r1 has no RP for $GROUP, see $WORKDIR/r1.log"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "3. It is the IGMP querier on both of its LANs"
	for i in ${EP}101b ${EP}104a; do
		if wait_for 60 iface_querier_is r1 "$i" Local; then
			ok "r1 queries $i itself, nobody else being there to"
		else
			fail "r1 reads the querier on $i as '$(iface_querier r1 "$i")', expected Local"
		fi
	done
	[ "$FAILED" -eq 0 ] || return 1

	print "4. A report on one LAN becomes a leaf, and the stream crosses"
	box_run ed2 "$MPING" -r -i "$SOLO_ED2_IF" -t 5 -W 90 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	if wait_for 60 has_mrt r1 "$GROUP"; then
		ok "r1 built ($GROUP) state from ED2's report"
	else
		fail "r1 never saw ED2's IGMP report, see $WORKDIR/r1.log"
		kill "$receiver" 2>/dev/null || true
		return 1
	fi
	box_run ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$STREAM_PKTS" -w 90 "$GROUP" \
		>"$WORKDIR/sender.log" 2>&1 || true
	kill "$receiver" 2>/dev/null || true
	wait "$receiver" 2>/dev/null || true

	replies=$(awk '/packets transmitted/ { print $4 }' "$WORKDIR/sender.log")
	replies=${replies:-0}
	if [ "$replies" -ge "$MIN_REPLIES" ]; then
		ok "ED1 -> $GROUP -> ED2 across one router, $replies replies"
	else
		fail "only $replies replies, want >= $MIN_REPLIES, see $WORKDIR/sender.log"
	fi
	[ "$FAILED" -eq 0 ] || return 1

	print "5. Being the RP itself, it registered the source to nobody"
	if register_oif_gone r1 "$SRC_ADDR" "$GROUP"; then
		ok "r1 kept the register vif out of the oifs for $SRC_ADDR"
	else
		fail "r1 is the RP for $GROUP and encapsulated $SRC_ADDR towards itself"
	fi
	rcvd=$(registers_rcvd r1)
	if [ "${rcvd:-0}" -eq 0 ]; then
		ok "and its kernel decapsulated no Register at all"
	else
		fail "r1's kernel took in $rcvd Register(s) on a router that is its own RP"
	fi

	print "6. The kernel MFC agrees with pimd"
	if has_mfc r1 "$GROUP"; then
		ok "r1 kernel has an MFC entry for $GROUP"
	else
		fail "r1 kernel MFC is empty, pimd never pushed the route down"
	fi

	result || {
		dprint "--- r1: pimctl show pim detail ---"
		pimctl r1 show pim detail 2>&1 | tail -40 || true
		dprint "--- r1: $MFC_SHOW_CMD ---"
		mfc_show r1 2>&1 || true
		return 1
	}
}

# Its status has a name of its own: sh has no locals, and "run all" keeps
# the verdict of the whole walk in rc, which a passing scenario after a
# failed one would otherwise put back to 0.
run_one() {
	one_rc=0
	start
	check || one_rc=$?
	[ "$SANITIZE" = no ] || stop_pimd
	check_sanitizer || one_rc=$?
	if [ "$one_rc" -ne 0 ]; then
		# stop() wipes the work directory, keep what failed
		saved="$WORKDIR.$SCENARIO.failed"
		${SUDO} rm -rf "$saved"
		${SUDO} cp -a "$WORKDIR" "$saved" 2>/dev/null || true
		echo "pimd logs and traffic captures kept in $saved"
	fi
	stop
	return $one_rc
}

# Scenarios started by run_parallel() and not yet reaped, "slot:name", and
# the shells they run in.  Globals because the INT handler is what reads
# them, and it runs in this shell however deep the loop below is.
PARALLEL_BUSY=
PARALLEL_PIDS=

parallel_abort() {
	trap - INT TERM

	echo
	print "Interrupted, taking down the labs that were still up ..."
	for pid in $PARALLEL_PIDS; do
		kill "$pid" 2>/dev/null || true
	done
	# The scenario shell is gone, its jails are not: each slot is asked
	# to stop itself, which is the same teardown a finished run does.
	for entry in $PARALLEL_BUSY; do
		sh "$LAB_SELF" -s "${entry%%:*}" stop >/dev/null 2>&1 || true
	done

	exit 130
}

# "run all -j N": N scenarios at a time, each in a lab slot of its own.
#
# Nothing here makes that safe -- the slot does, by naming every jail,
# link, bridge and work directory apart, so two scenarios never meet
# except on the host's CPUs and on net.inet.ip.mcast.loop, which
# disable_mcast_loop() has them take turns with.  What it costs is timing
# headroom: every assertion in this file polls with a timeout, and a host
# running eight labs converges more slowly than one running a single lab,
# so a job count well under the core count is worth more than one at it.
#
# Each scenario writes its output to a file and it is printed whole when
# the scenario ends.  Interleaved line by line the assertions of eight
# runs are unreadable, and worse, they are unattributable: every scenario
# here prints "ok 3." and means a different thing by it.
run_parallel() {
	jobs=$JOBS
	pending=$1

	[ -z "$WORKDIR_PINNED" ] || \
		die "WORKDIR is set in the environment, so every slot would" \
		    "share one work directory; unset it to run in parallel"

	last=$((SLOT + jobs - 1))
	[ "$last" -le 31 ] || \
		die "-j $jobs from slot $SLOT wants slots up to $last, and 31 is the last one"

	out=$(mktemp -d "${TMPDIR:-/tmp}/pimd-lab-parallel.XXXXXX")
	free=
	n=$SLOT
	while [ "$n" -le "$last" ]; do
		free="$free $n"
		n=$((n + 1))
	done

	results=
	rc=0

	trap parallel_abort INT TERM

	while [ -n "$pending" ] || [ -n "$PARALLEL_BUSY" ]; do
		while [ -n "$pending" ] && [ -n "$free" ]; do
			# shellcheck disable=SC2086
			set -- $pending; scenario=$1; shift; pending=$*
			# shellcheck disable=SC2086
			set -- $free; slot=$1; shift; free=$*

			print "===== scenario: $scenario, slot $slot, started ====="
			(
				# set +e because the redirection failing, or
				# the run itself, would otherwise take the
				# subshell out before it could say so; the
				# status is moved into place rather than
				# written there, so the file cannot be seen
				# half written by the loop below
				set +e
				sh "$LAB_SELF" -s "$slot" run "$scenario" \
					> "$out/$slot.log" 2>&1
				echo $? > "$out/$slot.rc.part"
				mv "$out/$slot.rc.part" "$out/$slot.rc"
			) &
			PARALLEL_PIDS="$PARALLEL_PIDS $!"
			PARALLEL_BUSY="$PARALLEL_BUSY $slot:$scenario"
		done

		sleep 2

		# A child cannot be waited for one at a time in POSIX sh, so
		# it says it is done by writing its exit status out.
		running=
		for entry in $PARALLEL_BUSY; do
			slot=${entry%%:*}
			scenario=${entry#*:}
			if [ ! -f "$out/$slot.rc" ]; then
				running="$running $entry"
				continue
			fi

			status=$(cat "$out/$slot.rc")
			print "===== scenario: $scenario, slot $slot, done ====="
			cat "$out/$slot.log"
			[ "$status" -eq 0 ] || rc=1
			results="$results $scenario:$status"
			mv "$out/$slot.log" "$out/$scenario.log"
			rm -f "$out/$slot.rc"
			free="$free $slot"
		done
		PARALLEL_BUSY=$running
	done

	trap - INT TERM
	wait

	echo
	print "===== $(echo $results | wc -w | tr -d " ") scenarios, $jobs at a time ====="
	for entry in $results; do
		if [ "${entry#*:}" -eq 0 ]; then
			printf "  \033[32mpass\033[0m  %s\n" "${entry%:*}"
		else
			printf "  \033[31mFAIL\033[0m  %s (exit %s)\n" \
			    "${entry%:*}" "${entry#*:}"
		fi
	done

	if [ "$rc" -eq 0 ]; then
		rm -rf "$out"
	else
		echo
		echo "per-scenario logs kept in $out"
	fi

	return $rc
}

# "run", "run <scenario>", "run <scenario> <scenario> ...", "run all".
# With -j the named scenarios are run several at a time, each in a slot of
# its own; without it they are run one after another, as they always were.
run() {
	rc=0

	if [ "${1:-}" = all ]; then
		# The same twenty-one either way, ordered by how long they
		# take when a pool is what picks them up
		if [ "$JOBS" -gt 1 ]; then
			list=$SCENARIOS_BY_LENGTH
		else
			list=$SCENARIOS
		fi
	elif [ $# -gt 1 ]; then
		list=$*
	else
		# One scenario, which is the common case: run it in this
		# shell, so its assertions reach the terminal as they are
		# made rather than in one block at the end.
		[ "$JOBS" -eq 1 ] || \
			die "-j needs more than one scenario to run in parallel"
		set_scenario "${1:-}"
		run_one || rc=$?
		exit $rc
	fi

	# Every name, before anything is built: a typo in the last of them
	# is worth hearing about now and not in twenty minutes.
	for s in $list; do
		set_scenario "$s"
	done

	if [ "$JOBS" -gt 1 ]; then
		run_parallel "$list" || rc=$?
		exit $rc
	fi

	for s in $list; do
		set_scenario "$s"
		print "===== scenario: $s ====="
		run_one || rc=$?
	done

	exit $rc
}

[ -z "$HELP" ] || { usage; exit 0; }

if [ $# -eq 0 ]; then
	usage
	exit 2
fi

cmd=$1
shift
case $cmd in
start)       set_scenario "${1:-}"; start ;;
check)       set_scenario "${1:-}"
	     rc=0
	     check || rc=$?
	     check_sanitizer || rc=$?
	     exit $rc ;;
run)         run "$@" ;;
stop)        stop ;;
*)           usage; exit 2 ;;
esac
