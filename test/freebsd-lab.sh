#!/bin/sh
# PIM-SM regression lab for FreeBSD, using vnet jails
#
# Exercises the FreeBSD-specific code paths of pimd that no CI covers: the
# rest of this directory is Linux-only, it is built on network namespaces,
# veth pairs and `unshare`, so on FreeBSD none of it can even start, and it
# is not in TESTS for that reason.  Everything asserted here goes through
# the kern.c BSD branches, and through routesock.c (RPF lookups over the
# PF_ROUTE socket) rather than netlink.c and the Linux ones.
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
# Fifteen scenarios are built on that topology.  Most differ only in which
# pimd.conf each router gets and which assertions run; rp-offpath adds one
# link to close the chain into a triangle; the two gif ones add a tunnel and
# take R2 out of PIM entirely; the two shared segment ones rebuild the two
# right hand links as bridged segments and hang two more routers off them;
# alias gives one interface a second address and moves the sender onto it;
# ifgone and renumber change a link under a pimd that is already running:
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
#               Takes about 5 minutes, it has to outlive PIM_DATA_TIMEOUT
#               (210s).
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
#               neighbour.  Takes about 90s.
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
#               matching the group on any interface at all.  Takes about
#               50s.
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
# Scenarios run in parallel, several labs at a time on one host: -s picks
# a slot, 0 to 31, and every name the lab puts on the host carries it, so
# slot 3's jails, epairs, bridges and work directory are not slot 0's.
# The addresses inside the jails are the same in every slot and can be,
# a vnet jail having an interface namespace and a forwarding cache of its
# own.  "-j N run all" does the bookkeeping: N scenarios at a time, each
# in a slot of its own, longest first, each one's output printed whole
# when it ends.  Measured on a 16-core host, 4m35s at -j 4 and 4m11s at
# -j 14, which was the whole list when it was taken, against the half hour
# they take one after another.  The two are close because keepalive is a floor no job count
# moves: it has to outlive PIM_DATA_TIMEOUT, so it runs 240s whatever
# else is happening.
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
#   ./freebsd-lab.sh [-s SLOT] start [scenario]  build the lab, start pimd on its routers
#   ./freebsd-lab.sh [-s SLOT] check [scenario]  run the assertions (start must have run)
#   ./freebsd-lab.sh [-s SLOT] run   [scenario]  start + check + stop, exit 0 if all pass
#   ./freebsd-lab.sh [-s SLOT] stop              tear that slot down
#   ./freebsd-lab.sh -j 4 run all                every scenario, four at a time
#   ./freebsd-lab.sh -j 3 run shared-lan shared-lan-spt assert-recover
#                                                three of them, all at once
#
# where scenario is "rpt" (default), "keepalive", "rp-lasthop",
# "rp-offpath", "gif-tunnel", "gif-tunnel-staticrp", "shared-lan",
# "shared-lan-spt", "assert-recover", "ssm", "ssm-range", "alias",
# "ifgone", "renumber", "register-filter", or "all" for run.
#
# Requires: root (via sudo), VIMAGE kernel, ip_mroute.ko, if_bridge.ko for
# the shared segment scenarios, and a built pimd tree in $PIMD_SRC (./autogen.sh &&
# ./configure && gmake).  With NETLINK=yes, that tree has to be configured
# --enable-netlink and netlink.ko has to be loadable.

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
JAIL_PREFIX=pimd${TAG}_

# The ifconfig(8) group every interface this lab creates is put in, so a
# human can find or destroy one lab's links and not another's.  The slot
# is spelled in letters, digit by digit -- slot 0 is "pimda" and slot 31
# "pimddb" -- because a group name may not end in a digit: it would be
# ambiguous with an interface name, and setifgroup refuses it outright.
IFGROUP=pimd$(echo "$SLOT" | tr 0-9 a-j)

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
SCENARIOS="rpt keepalive rp-lasthop rp-offpath gif-tunnel gif-tunnel-staticrp
	   shared-lan shared-lan-spt assert-recover ssm ssm-range alias
	   ifgone renumber register-filter"
SCENARIOS_BY_LENGTH="keepalive shared-lan assert-recover shared-lan-spt
		     gif-tunnel-staticrp rp-lasthop rp-offpath gif-tunnel
		     rpt register-filter alias ssm ifgone renumber ssm-range"

# keepalive: groups the source blasts at, and how long the entries must
# survive.  KEEP_SECONDS has to exceed PIM_DATA_TIMEOUT in src/pimd.h.
KEEP_GROUP=${KEEP_GROUP:-239.1.1.5}
KEEP_NUM=${KEEP_NUM:-3}
KEEP_SECONDS=${KEEP_SECONDS:-240}

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

# pimd debug flags, e.g. DEBUG="-l debug -d mrt,rpf" or "-l debug -d all"
DEBUG=${DEBUG:-"-l debug -d mrt,rpf,pim_register,pim_bootstrap"}

PIMD="$PIMD_SRC/src/pimd"
PIMCTL="$PIMD_SRC/src/pimctl"
MPING="$WORKDIR/mping"
IGMPV3="$WORKDIR/igmpv3"
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
OFFPATH_R1_IF=${EP}113a
OFFPATH_R3_IF=${EP}113b
OFFPATH_R1_ADDR=10.0.13.1
OFFPATH_R3_ADDR=10.0.13.3
# The RP and the BSR sit on R2's interface facing the last hop router, so
# R3 is directly connected to both, see write_configs()
OFFPATH_RP_ADDR=10.0.23.2

# Everything any scenario can create, so stop() cleans up without having to
# be told which one was running.
ALL_BOXES="ed1 r1 r2 r3 r4 r5 ed2 ed3"
ALL_EPAIRS="$EPAIRS $SHARED_EPAIRS ${EP}113"

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

# ssm-range: the range pimd.conf configures, a group inside it, and the
# group from the default range that has to stop being source specific once
# the configured one replaces it.
SSMR_RANGE=${SSMR_RANGE:-239.232.0.0/16}
SSMR_GROUP=${SSMR_GROUP:-239.232.1.1}
SSMR_OLD_GROUP=${SSMR_OLD_GROUP:-232.1.1.1}
SSMR_DEFAULT_RANGE=232.0.0.0/8

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

# ifgone: the link that is destroyed under R1, named from both ends
# because an epair can only be destroyed from the jail that owns an end,
# and both ends of this one live in jails.  IFGONE_KEPT is the address on
# R1's other interface, the one the register VIF has to fall back to.
IFGONE_IF=${IFGONE_IF:-${EP}101b}
IFGONE_PEER_IF=${IFGONE_PEER_IF:-${EP}101a}
IFGONE_ADDR=${IFGONE_ADDR:-10.0.1.1}
IFGONE_KEPT=${IFGONE_KEPT:-10.0.12.1}
IFGONE_KEPT_IF=${IFGONE_KEPT_IF:-${EP}112a}

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
	rpt|keepalive|rp-lasthop|rp-offpath|gif-tunnel|gif-tunnel-staticrp|shared-lan|shared-lan-spt|ssm|ssm-range|alias|ifgone|renumber|assert-recover|register-filter)
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
	r1) echo "$ALIAS_IF $ALIAS_ADDR/24" ;;
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
	alias)
		# The sender only lives on the aliased subnet, so that is the
		# prefix the rest of the domain has to route towards R1 and
		# the one every RPF lookup for the source asks about.
		case $1 in
		ed1) echo "default $ALIAS_ADDR" ;;
		r1)  echo "10.0.23.0/24 10.0.12.2 10.0.3.0/24 10.0.12.2" ;;
		r2)  echo "$ALIAS_NET 10.0.12.1 10.0.3.0/24 10.0.23.3" ;;
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
	case $SCENARIO in
	shared-lan|assert-recover)
		case $1 in
		r3|r4) echo "$SL_RP_NET $SL_RP_GW $SL_METRIC_FAR" ;;
		esac
		;;
	esac
}

jname() { echo "$JAIL_PREFIX$1"; }

jrun() { j=$1; shift; ${SUDO} jexec "$(jname "$j")" "$@"; }

pimctl() { j=$1; shift; jrun "$j" "$PIMCTL" -u "$WORKDIR/$j.sock" "$@"; }

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
	[ "$(sysctl -n kern.features.vimage 2>/dev/null || echo 0)" = "1" ] || \
		die "kernel has no VIMAGE support, cannot create vnet jails"
	[ -x "$PIMD" ] || die "$PIMD not found, build it first (PIMD_SRC=$PIMD_SRC)"
	[ -x "$PIMCTL" ] || die "$PIMCTL not found, build it first"
	[ -f "$PIMD_SRC/test/mping.c" ] || die "$PIMD_SRC/test/mping.c not found"
	[ -f "$PIMD_SRC/test/igmpv3.c" ] || die "$PIMD_SRC/test/igmpv3.c not found"
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
		# R1: DR for $SRC_ADDR *and* RP for the groups it sends to
		spt-threshold infinity
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
		jrun "$box" ifconfig "$1" name "$2"
		shift 2
	done

	set -- $(addrs "$box")
	while [ $# -ge 2 ]; do
		jrun "$box" ifconfig "$1" inet "$2" up
		shift 2
	done

	# After the addresses: "alias" is what keeps the kernel from
	# replacing the address the interface already has
	set -- $(aliases "$box")
	while [ $# -ge 2 ]; do
		jrun "$box" ifconfig "$1" inet "$2" alias
		shift 2
	done

	# Before the routes: gif-tunnel points some of them at $GIF_R1/$GIF_R3
	set -- $(tunnels "$box")
	while [ $# -ge 5 ]; do
		jrun "$box" ifconfig "$1" create
		jrun "$box" ifconfig "$1" tunnel "$2" "$3"
		jrun "$box" ifconfig "$1" inet "$4" "$5" netmask "$GIF_MASK" up
		shift 5
	done

	set -- $(routes "$box")
	while [ $# -ge 2 ]; do
		jrun "$box" route -q add "$1" "$2" >/dev/null
		shift 2
	done

	# After the routes: a metric is a property of one that already exists
	set -- $(route_metrics "$box")
	while [ $# -ge 3 ]; do
		jrun "$box" route -q change "$1" "$2" -metric "$3" >/dev/null
		shift 3
	done

	case $box in
	r*) jrun "$box" sysctl -q net.inet.ip.forwarding=1 >/dev/null ;;
	esac
}

destroy_box() {
	box=$1
	name=$(jname "$box")

	jls -j "$name" jid >/dev/null 2>&1 || return 0
	${SUDO} jail -r "$name" 2>/dev/null || true
}

# Start pimd on one router.  Split out of start() so that a scenario can
# restart a single daemon in the middle of a run: the command line has to
# be the same one, or the router that comes back is not the one the rest of
# the scenario was written against.  daemon(8) opens the log with O_APPEND,
# so what the first incarnation logged is still there afterwards.
start_pimd() {
	r=$1

	# shellcheck disable=SC2086
	${SUDO} daemon -f -p "$WORKDIR/$r.daemon.pid" \
		-o "$WORKDIR/$r.log" \
		jexec "$(jname "$r")" "$PIMD" -i "$r" -n $DEBUG \
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

	if jls -j "$(jname r1)" jid >/dev/null 2>&1; then
		die "lab already running, run '$0 stop' first"
	fi

	# Owned by the invoking user: pimd runs as root and can still drop its
	# PID file and control socket in here, but mping is built unprivileged.
	mkdir -p "$WORKDIR"

	print "Building mping (multicast ping) from the pimd tree ..."
	cc -O2 -o "$MPING" "$PIMD_SRC/test/mping.c" || \
		die "failed building $PIMD_SRC/test/mping.c"

	print "Building igmpv3 (membership report generator) ..."
	cc -O2 -o "$IGMPV3" "$PIMD_SRC/test/igmpv3.c" || \
		die "failed building $PIMD_SRC/test/igmpv3.c"

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
		${SUDO} daemon -f -p "$WORKDIR/msend.pid" -o "$WORKDIR/msend.log" \
			jexec "$(jname ed1)" "$MSEND" "$SRC_ADDR" "$KEEP_GROUP" "$KEEP_NUM"
	fi

	print "Lab is up ($SCENARIO).  Poke at it with:"
	echo "  ${SUDO} jexec $(jname r2) $PIMCTL -u $WORKDIR/r2.sock show pim detail"
	echo "  ${SUDO} jexec $(jname r3) netstat -gn"
	echo "  ${SUDO} jexec $(jname ed2) $MPING -r -i $ED2_IF $GROUP"
	echo "  tail -f $WORKDIR/r1.log"
}

# --- assertions -------------------------------------------------------

has_neighbor() { pimctl "$1" show neighbor 2>/dev/null | grep -q "$2"; }
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
has_mrt()      { pimctl "$1" show mrt 2>/dev/null | grep -q "$2"; }
has_mfc()      { jrun "$1" netstat -gn 2>/dev/null | grep -q "$2"; }

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

	jrun "$1" netstat -gn 2>/dev/null | awk -v s="$SRC_ADDR" -v g="$3" -v v="$idx" '
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
	jrun ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$STREAM_PKTS" -w 90 "$GROUP" \
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
	jrun ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$STREAM_PKTS" -w 90 "$GROUP" \
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
	jrun "$1" route -q change "$SL_RP_NET" "$SL_RP_GW" -metric "$2" >/dev/null
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

	jrun ed3 "$MPING" -r -i ${EP}603b -p "$SL_JOIN_PORT" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/joiner-metric.log" 2>&1 &
	joiner=$!
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
		>"$WORKDIR/receiver-metric.log" 2>&1 &
	receiver=$!
	jrun ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$SL_METRIC_PKTS" \
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
	jrun r4 ifconfig "$SL_R4_IF" inet "$AR_DR_NEW" delete 2>/dev/null || true
	jrun r4 ifconfig "$SL_R4_IF" inet "$SL_DR_ADDR/24" alias 2>/dev/null || true
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
		dprint "--- $r: netstat -gn ---"
		jrun "$r" netstat -gn 2>&1 || true
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	jrun ed3 "$MPING" -r -i ${EP}603b -p "$SL_JOIN_PORT" -t 5 -W 900 "$GROUP" \
		>"$WORKDIR/joiner-recover.log" 2>&1 &
	joiner=$!
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 900 "$GROUP" \
		>"$WORKDIR/receiver-recover.log" 2>&1 &
	receiver=$!
	jrun ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$AR_PKTS" -w "$AR_PKTS" "$GROUP" \
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
	jrun r4 ifconfig "$SL_R4_IF" inet "$SL_DR_ADDR" delete
	jrun r4 ifconfig "$SL_R4_IF" inet "$AR_DR_NEW/24" alias
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
	jls -j "$(jname r1)" jid >/dev/null 2>&1 || die "lab is not running, run '$0 start'"

	# "run all" walks the scenarios in one shell, and every check_*()
	# gates its later assertions on "[ $FAILED -eq 0 ] || return 1".
	# Without this the first scenario to fail takes every scenario after
	# it down at its first checkpoint, with all of their assertions
	# printing ok on the way out - a clean looking run that tested
	# nothing.
	FAILED=0
	XFAILED=0

	case $SCENARIO in
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
	ifgone)     check_ifgone; return $? ;;
	renumber)   check_renumber; return $? ;;
	register-filter) check_register_filter; return $? ;;
	esac

	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	print "4. Multicast is forwarded from ED1 to ED2 through the RP"
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 90 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	sleep 2
	jrun ed1 "$MPING" -s -i ${EP}101a -t 5 -c 40 -w 60 "$GROUP" \
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

	print "5. pimd installed the route it claims to have"
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

	print "6. The kernel MFC in each vnet agrees with pimd"
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
	jrun "$1" netstat -sp pim 2>/dev/null | \
		awk '/data register messages? received$/ { print $1; exit }'
}

# Let ED1 send to the group with nobody listening.  mping counts replies and
# exits non-zero when it gets none, which here is the expected outcome.
regf_send() {
	jrun ed1 "$MPING" -s -i "${EP}101a" -t 5 -c "$REGF_PKTS" \
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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

	print "9. The same Registers are now acted on"
	dprint "sending another $REGF_PKTS packets to $GROUP ..."
	regf_send
	if wait_for 60 logged r1 "Received PIM_REGISTER_STOP"; then
		ok "r1 got its Register-Stop"
	else
		fail "r1 got no Register-Stop, the RP accepted but never answered"
		return 1
	fi
	# The DR acting on it, which is what tells a Register-Stop that arrived
	# from one that was merely logged, and the mirror of assertion 3:
	# suppress_register() (src/pim_proto.c) prunes PIMREG_VIF, so the vif
	# that was in the oif list while the RP refused leaves it once the RP
	# answers.  Asked of the oif list and not of the Register-Suppression
	# timer beside it, which is seeded with a random half of
	# PIM_REGISTER_SUPPRESSION_TIMEOUT and can run out inside a poll.
	if wait_for 30 register_oif_gone r1 "$SRC_ADDR" "$GROUP"; then
		ok "r1 dropped the register vif from ($SRC_ADDR,$GROUP), it stopped encapsulating"
	else
		fail "r1 still forwards ($SRC_ADDR,$GROUP) out the register vif, the Register-Stop changed nothing"
	fi

	result
}

# For wait_for(): has the register vif left the oif list of ($2,$3) on $1?
# Position 0 of the "Outgoing oifs" map is PIMREG_VIF, see route_oifs().
register_oif_gone() {
	[ "$(route_oifs "$1" "$2" "$3" | cut -c1)" != "o" ]
}

# The register-accept-from list r2 is running with, for wait_for(): a
# reload has to be given time to land, and "show status" is where the
# running list shows.
regf_acl_is() {
	pimctl "$1" show status 2>/dev/null | \
		grep -q "Register accept list *: *$2"
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	jrun ed2 "$IGMPV3" -i "$RCV_ADDR" -g "$grp" "$@" || \
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

# Local address the kernel holds for one VIF index, out of "netstat -gn".
# VIF 0 is the register VIF: uvifs[0] is reserved for it, which is why
# config_vifs_from_kernel() starts its loop at 1 (src/config.c), and the
# kernel index is the same one.
kern_vif_addr() {
	jrun "$1" netstat -gn 2>/dev/null | awk -v v="$2" '$1 == v { print $3 }'
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

	# ifmcstat exits non-zero for a name it cannot resolve, and the
	# assignment would take "set -e" with it -- inside the command
	# substitution this runs in, that is a subshell leaving quietly and a
	# caller reading an empty answer as "nothing missing".  An interface
	# that cannot be read holds nothing we can prove it holds, so say so.
	mg_held=$(jrun "$mg_box" ifmcstat -i "$mg_if" -f inet 2>/dev/null) || mg_held=
	for mg_group in "$@"; do
		echo "$mg_held" | grep -q "group $mg_group\b" || printf '%s ' "$mg_group"
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 90 "$GROUP" \
		>"$WORKDIR/receiver.log" 2>&1 &
	receiver=$!
	sleep 2
	jrun ed1 "$MPING" -s -i ${EP}101a -t 5 -c 40 -w 60 "$GROUP" \
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

	echo
	if [ "$FAILED" -eq 0 ]; then
		print "RESULT: PASS"
		return 0
	fi
	print "RESULT: FAIL ($FAILED assertion(s))"
	dprint "--- r1: ifconfig $ALIAS_IF ---"
	jrun r1 ifconfig "$ALIAS_IF" 2>&1 || true
	for r in $ROUTERS; do
		dprint "--- $r: pimctl show pim detail ---"
		pimctl "$r" show pim detail 2>&1 | tail -40 || true
	done
	return 1
}

check_ifgone() {
	print "1. pimd is alive on every router"
	for r in $ROUTERS; do
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	jrun ed1 ifconfig "$IFGONE_PEER_IF" destroy || \
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	jrun r2 ifconfig "$RENUM_IF" inet "$RENUM_OLD" delete || \
		die "failed removing $RENUM_OLD from $RENUM_IF on r2"
	jrun r2 ifconfig "$RENUM_IF" inet "$RENUM_NEW/24" alias || \
		die "failed adding $RENUM_NEW to $RENUM_IF on r2"
	# The unicast routing follows the address, as it would in the field:
	# R3 reaches the source and the RP through the gateway that just moved.
	for net in 10.0.1.0/24 10.0.12.0/24; do
		jrun "$RENUM_PEER" route -q change "$net" "$RENUM_NEW" >/dev/null 2>&1 || \
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
	if pimctl r1 show status >/dev/null 2>&1; then
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
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
	dprint "--- r3: netstat -gn ---"
	jrun r3 netstat -gn 2>&1 || true
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
	jrun ed1 "$MPING" -s -i ${EP}101a -t 5 -c "$STREAM_PKTS" -w 90 "$GROUP" \
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
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
		dprint "--- $r: ifconfig $GIF_IF ---"
		jrun "$r" ifconfig "$GIF_IF" 2>&1 | head -4 || true
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
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
		if pimctl "$r" show status >/dev/null 2>&1; then
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
	jrun ed3 "$MPING" -r -i ${EP}603b -p "$SL_JOIN_PORT" -t 5 -W 300 "$GROUP" \
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
	jrun ed2 "$MPING" -r -i "$ED2_IF" -t 5 -W 300 "$GROUP" \
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
		dprint "--- $r: netstat -gn ---"
		jrun "$r" netstat -gn 2>&1 || true
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

	# Jails can linger in the dying state and hold their interfaces
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

	restore_mcast_loop
	${SUDO} rm -rf "$WORKDIR"
}

run_one() {
	rc=0
	start
	check || rc=$?
	if [ "$rc" -ne 0 ]; then
		# stop() wipes the work directory, keep what failed
		saved="$WORKDIR.$SCENARIO.failed"
		${SUDO} rm -rf "$saved"
		${SUDO} cp -a "$WORKDIR" "$saved" 2>/dev/null || true
		echo "pimd logs and traffic captures kept in $saved"
	fi
	stop
	return $rc
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
		"$0" -s "${entry%%:*}" stop >/dev/null 2>&1 || true
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
				"$0" -s "$slot" run "$scenario" \
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
		# The same fifteen either way, ordered by how long they
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
start|check) set_scenario "${1:-}"; $cmd ;;
run)         run "$@" ;;
stop)        stop ;;
*)           usage; exit 2 ;;
esac
