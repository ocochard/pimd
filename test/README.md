pimd Test Suites
================

Three suites live in this directory.  They are not three ways of running
the same tests: each one reaches code and situations the other two
cannot, and a change is only really covered when the suite that can see
it has run.

* The **Linux suite** is `make check`.  It builds router topologies out
  of network namespaces and veth pairs, and exercises `netlink.c` and the
  Linux kernel glue.  CI runs it on every push.
* The **FreeBSD vnet jail lab** builds the same kind of topologies out
  of vnet jails and epairs, and is the only thing that exercises
  `routesock.c` and the BSD branches of `kern.c` rather than merely
  compiling them.  It also holds the scenarios that reproduce specific
  upstream issues.  CI runs it on every push too, in a FreeBSD VM.
* The **Arista vEOS interoperability lab** puts a foreign PIM
  implementation on the wire.  The other two have pimd on both ends of
  every exchange, so a message pimd encodes wrongly is a message pimd
  decodes wrongly in the same way and the run stays green.  This one
  catches that.

Only the first is part of `make check`, because automake drives `TESTS`
under `unshare -mrun` and that is Linux.  The other two are shell scripts
run on their own: both need root and a couple of kernel modules loaded
beforehand, and the third also needs a licensed VM image, which is why it
is the one CI cannot run.


Table of Contents
-----------------

* [Shared tools](#shared-tools)
* [The Linux suite](#the-linux-suite)
* [The FreeBSD vnet jail lab](#the-freebsd-vnet-jail-lab)
* [The Arista vEOS interoperability lab](#the-arista-veos-interoperability-lab)
* [Which suite sees what](#which-suite-sees-what)


Shared tools
------------

| File        | What it is                                                  |
|-------------|-------------------------------------------------------------|
| `mping.c`   | Multicast ping.  `-s` sends to a group, `-r` joins it and answers each packet by sending to the same group, so one run builds a tree in each direction.  The sender's "packets transmitted" line counts the replies that came back, which is how every forwarding assertion is measured. |
| `igmpv3.c`  | Sends exactly one IGMPv3 membership report and exits.  Needed wherever a test has to watch a membership *age out*: a kernel that joined a group answers every query afterwards, so the membership never expires while the emulated device is on the LAN. |
| `lib.sh`    | Helpers for the Linux suite: `topo()` builds the namespaces and links, `ifsetup()` addresses them, `emitter()`/`collect()` wrap `mping`. |

`mping` and `igmpv3` are built by `configure --enable-test`; the two
FreeBSD labs compile them on their own when they start.


The Linux suite
---------------

Automake test suite, driven by `TESTS_ENVIRONMENT = unshare -mrun`.
Every script builds its topology from network namespaces, veth pairs and
bridges, starts one pimd per namespace, and asserts on forwarded
traffic.  The ASCII diagram in each script header is the topology.

    ./configure --enable-test
    make check                       # all of them
    make check TESTS=rp.sh           # one, from test/ or the top directory
    make check || cat test/test-suite.log

Needs root plus `ethtool`, `tshark` and `bird`.  `bird` runs OSPF, which
is what builds the unicast RPF tree PIM depends on; `ethtool` disables
UDP checksum offloading, since frames leave kernel space on these veth
pairs.  A missing dependency makes a test **SKIP** (exit 77), not fail,
so a green run on a machine without them has tested nothing — check the
log.

Set `DEBUG="-l debug -d all"` at the top of a script to get pimd logs
and runtime `pimctl` dumps.

| Test        | Topology                    | What it asserts                          |
|-------------|-----------------------------|------------------------------------------|
| `single.sh` | One router, two end devices | Forwarding between two LANs on one router, and an IGMPv3 query on both. |
| `two.sh`    | Two routers in a row        | The same, with the sender starting *before* the receiver joins — the other tests do it the other way round. |
| `three.sh`  | Three routers in a row      | Forwarding across two transit hops. |
| `rp.sh`     | Triangle, R2 is the RP      | Rendez-vous Point operation and the switch to the shortest path tree.  R2 is the RP and R3 the last hop router, on separate routers. |
| `shared.sh` | Two routers, both LANs bridged | Two routers on one shared segment at each end. |
| `pod.sh`    | Four routers, redundant paths | Two disjoint paths between the same pair of LANs. |
| `ssm.sh`    | One router, one end device  | IGMPv3 (S,G) membership state, not forwarding: two sources reported for one SSM group, one blocked, and the survivor still ageing out once the reports stop.  Driven by `igmpv3.c`, for the reason given above. |


The vnet jail and network namespace lab
---------------------------------------

    sh test/lab.sh run all          # every scenario, one after another
    sh test/lab.sh -j 4 run all     # four at a time, ~4.5 min instead of ~31
    sh test/lab.sh run rp-offpath   # one of them
    sh test/lab.sh start rpt        # build it and leave it up
    sh test/lab.sh check rpt        # assertions against a running lab
    sh test/lab.sh stop

Deliberately **not** in `TESTS`, which automake runs under `unshare
-mrun`, a Linux command.  What the lab itself wants is root, and
`ip_mroute.ko` plus `if_bridge.ko` for the shared segment scenarios
loaded before it starts, because a jail may not `kldload`.  Nothing there
calls for a custom kernel: GENERIC is built with VIMAGE and ships both
modules.  The Linux suite cannot run on FreeBSD at all, so without this
lab the BSD half of the tree is compiled but never executed.

Run as root the lab uses no `sudo` at all; as an ordinary user it wraps
every privileged command in one, and `SUDO=` in the environment overrides
that either way.

`NETLINK=yes` runs the same scenarios against the other RPF backend.
FreeBSD 13.2 and later answer the lookups `routesock.c` makes over the
routing socket through `netlink(4)` as well, and a tree configured
`--enable-netlink` builds `netlink.c` for them instead, the same file
Linux uses.  Nothing about a running lab betrays which one is in there,
both answer the same lookups, so before asserting anything the lab asks
`pimctl show status` what the daemon was built with and stops if it is
not what was asked for.  `netlink.ko` has to be loadable, for the same
reason as `ip_mroute.ko`.

`SANITIZE=yes` runs the same scenarios against a pimd built with
AddressSanitizer and UndefinedBehaviorSanitizer, and fails a scenario
whose daemons reported anything, whatever its assertions found.  Build
that tree separately and point `PIMD_SRC` at it:

    ./configure --prefix= CFLAGS="-g -O1 -fsanitize=address,undefined \
        -fno-omit-frame-pointer" LDFLAGS="-fsanitize=address,undefined"
    SANITIZE=yes PIMD_SRC=/path/to/that/tree ./test/lab.sh -j 10 run all

The lab does not build it, and does not take the tree on trust either: it
asks the binary for a sanitizer runtime and stops if there is none.  Each
daemon writes its reports to files of its own under the work directory,
because the two sanitizers behave differently — ASan stops the daemon at
its first error, which the assertions notice by themselves, while UBSan
prints and carries on, so its findings would leave with the work
directory of a scenario that passed.  Leak checking is off, ASan turning
it on at exit on Linux: what leaks in a daemon being torn down is a hunt
of its own.  `SAN_ASAN_OPTIONS=detect_leaks=1` asks for it anyway.

Both sanitizers slow a router down, so a scenario measuring a timer can
want a smaller `-j` than the same run without them.

What makes it possible: `sys/netinet/ip_mroute.c` is fully VNET-ized, so
each vnet jail owns a private forwarding cache and vif table, and
`prison_priv_check()` grants `PRIV_NETINET_MROUTE`, `PRIV_NETINET_RAW`
and `PRIV_NET_BPF` to jails with their own network stack, so pimd's raw
sockets and `MRT_INIT` work inside one.  `ip_mroute.ko` has to be loaded
from the host, a jail may not `kldload`.

The scenarios never reach the host directly.  Everything that builds a
box, runs a command in one, changes an interface or a route under it, or
reads the kernel's multicast state back is a function in
`test/lab-freebsd.sh`, which `lab.sh` sources; its header lists
them.  `test/lab-linux.sh` is the same functions over named network
namespaces, veth pairs and Linux bridges, and the script picks one by
`uname -s`, so on a Linux host, as root,

    ./test/lab.sh -j 19 run all

runs the same nineteen scenarios against the Linux kernel and `netlink.c`.
It needs iproute2, ethtool and a kernel with `CONFIG_IP_MROUTE` and
`CONFIG_IP_PIMSM_V2`.  Unlike the automake suite it does not run under an
unprivileged `unshare`: a box has to outlive the command that built it.

Most scenarios share one topology, a chain of three routers with an end
device at each end; the ones that do not say so below.  Unicast routing
is static on purpose — a static route carries a metric of its own, which
`route change -metric` moves and pimd reads back out of the kernel for
its Asserts, so a routing daemon here would only add a dependency and a
second thing to debug.  The administrative distance pimd puts beside
that metric does still come from `pimd.conf`, and no routing daemon
would change that either — deviation **M4** in
`doc/rfc7761-compliance.md`.

An assertion that reproduces a known deviation reports **KNOWN** through
`xfail()` instead of failing the run, and turns into an `ok` the day
pimd starts doing the right thing.

Scenarios run in parallel, several labs at a time — `-s` and `-j` below.

| Scenario              | Time | What only this one covers |
|-----------------------|------|---------------------------|
| `rpt`                 | ~90s | The baseline: R2 is BSR and RP, the receiver joins, traffic has to arrive over the shared tree. |
| `keepalive`           | ~5m  | An (S,G) with an empty outgoing interface list, kept alive while its source sends — [issue #251][251].  Runs long on purpose, it has to outlive `PIM_DATA_TIMEOUT` (210s). |
| `rp-lasthop`          | ~2m  | The RP *is* the last hop router for the only receiver — [issue #243][243].  `rp.sh` keeps those two roles on separate routers, so the RP there never has a directly connected member. |
| `rp-offpath`          | ~2m  | The only topology that is not a chain.  A triangle puts the RP off the path the traffic takes once the SPT is up, so the shared tree and the shortest path tree leave a router by different interfaces, and the last hop router is directly connected to the BSR — [issue #211][211]. |
| `gif-tunnel`          | ~2m  | Two PIM routers either side of a plain unicast transit router, joined by a `gif` tunnel.  A gif is `IFF_POINTOPOINT`, so this is the only scenario reaching the point-to-point branch of `config_vifs_from_kernel()`. |
| `gif-tunnel-staticrp` | ~3m  | The same tunnel with a static `rp-address` instead of an elected RP.  A different code path, not another route to the same state: `my_cand_rp_address` is only ever set while parsing `cand_rp`, so with a static RP the router that *is* the RP answers "no" to every internal test of whether it is. |
| `shared-lan`          | ~3m  | Five routers over two bridges, three of them on one segment.  The only scenario with more than one PIM router on a link, so the only one where DR election, IGMP querier election and the assert election run at all.  Its addresses put the DR and the querier on different routers, the two elections taking opposite ends of the address range. |
| `shared-lan-spt`      | ~3m  | The same LAN with the last hop router allowed onto the SPT, which by RFC 7761 4.6.1 must decide the assert on the RPT bit before either address is looked at.  Holds the one `xfail()` written so far — pimd took the bit straight from `MRTF_RP` and lost a comparison it should have won.  Now reports `ok`, fixed in `4cb79f1`. |
| `ssm`                 | ~90s | IGMPv3 (S,G) membership on the last hop router, the FreeBSD counterpart to `ssm.sh`. |
| `ssm-range`           | ~30s | The SSM range moved off 232.0.0.0/8 by `ssm-range` in `pimd.conf` — [issue #185][185].  The configured range *replaces* the default, like Cisco's, so both halves are asserted at once: a group in the new range becomes source specific and one in 232/8 stops being. |
| `alias`               | ~90s | An interface carrying a second address, on a subnet of its own, with the sender on that second subnet.  The only scenario reaching the alias branch of `config_vifs_from_kernel()`, and one Linux cannot show: on BSD a dropped alias means the DR does not believe the sender is on its LAN and never registers it. |
| `ifgone`              | ~50s | An interface destroyed under a running pimd — [issue #218][218].  FreeBSD answers `ENXIO` where Linux answers `ENODEV`, and `check_vif_state()` used to know only the Linux one.  Also asks the link that survived what groups it is still a member of, which is where the leave for the one that went used to take them. |
| `renumber`            | ~50s | The counterpart: the interface stays and its address moves, inside its own subnet.  Asserts that pimd notices, takes the VIF out of service and back in, that the neighbour on the far side sees the new address without waiting for a periodic Hello, and that neither link lost a group membership on the way — a neighbour outlives the membership that feeds it, so it has to be asked for separately. |

Set `DEBUG` at the top of the script for pimd logs; each router's log
and control socket land in `/tmp/pimd-test`, or `/tmp/pimd-testN` for a
lab started with `-s N`.

### Several labs at once

`-s SLOT`, 0 to 31, picks which lab an invocation is.  Everything the lab
puts on the host carries the slot — the jails (`pimd3_r1`), the epairs
(`epair3101a`), the bridges, the interface group and the work directory
(`/tmp/pimd-test3`) — so labs in different slots cannot see, or tear
down, each other:

    sh test/lab.sh -s 1 start shared-lan    # one lab
    sh test/lab.sh -s 2 start rp-offpath    # another, beside it
    sh test/lab.sh -s 1 stop                # just that one

The addresses inside the jails are the same in every slot and can be: a
vnet jail has an interface namespace, a routing table and a multicast
forwarding cache of its own.  What the slots do share is
`net.inet.ip.mcast.loop`, which is not VNET-ized, so they hold it between
them under a lock and the last one to stop puts the host value back —
`freebsd-interop.sh` takes part in the same count.

`-j JOBS` runs several scenarios at a time, one slot each, and prints
each one's output whole when it ends rather than interleaving them:

    sh test/lab.sh -j 4 run all
    sh test/lab.sh -j 3 run shared-lan shared-lan-spt assert-recover

`-j N run all` walks the scenarios longest first, so the pool does not end
up running `keepalive` alone with three slots idle.  Measured on a
16-core host: `-j 4` 4m35s, `-j 14` — every scenario at once — 4m11s,
against the half hour the per-scenario times above add up to.  The two
are so close because `keepalive` is a floor no job count moves: it runs
`KEEP_SECONDS` 240s to outlive `PIM_DATA_TIMEOUT`, so nothing finishes in
much under four minutes.

Every assertion here is a poll against a timeout, so a slower lab can
fail an assertion rather than merely take longer.  Measured on a 16-core
host, though, what a pool costs is not load: fourteen labs at once is a
load average under one, `-j 14` passed all fourteen scenarios, and a
scenario run alone beside three slots churning labs up and down passed
too.

What a pool does change is which states the scenarios reach, and that has
already paid for itself.  `shared-lan-spt` failed assertion 9 — *both r3
and r4 still forward, no assert settled it* — in all three `-j 4 run all`
runs while passing on its own in any slot, and it was reporting a real
pimd deviation rather than a harness artifact: R3 never set SPTbit for
the source, so it asserted as an RPT forwarder, the two `MRTF_SPT` guards
in `assert_machine()` had each router decline the other's Assert, and the
LAN was left with two forwarders permanently.  The pool is what leaves a
router the Assert loser on its own RPF interface often enough to reach
that state; a sequential run never provoked it.  Fixed in `076343d` —
`update_sptbit()` asks the shared tree's olist now, not whether a `(*,G)`
entry exists — and `-j 4 run all` has been 14 of 14 since.  Run the pool
for that, not despite it.  `rp-lasthop` failed once in four runs and has
not repeated.


The Arista vEOS interoperability lab
------------------------------------

    sh test/freebsd-interop.sh -i ~/vEOS64-lab-4.36.1F.qcow2 run all
    sh test/freebsd-interop.sh -i ~/vEOS.qcow2 run pimd-rp     # one of them
    sh test/freebsd-interop.sh -i ~/vEOS.qcow2 start assert-lan # leave it up
    sh test/freebsd-interop.sh stop                            # no image needed

    sh test/freebsd-interop.sh -i ~/vEOS.qcow2 -j 3 run all    # three at a time
    sh test/freebsd-interop.sh -i ~/vEOS.qcow2 -s 2 run pimd-rp  # in slot 2

`-i` names the vEOS-lab qcow2 image, and there is no default: it is a
licensed Arista download that cannot ship with this tree, so where it
lives is yours to say.  `$VEOS_QCOW` works instead of the flag.

### Getting the image

One file, from the *Software Download* area of [arista.com][arista-dl],
under **vEOS-lab**.  It needs an Arista account, which is free to
register; the vEOS-lab licence covers lab and evaluation use, which is
what this is.

| | |
|---|---|
| File          | `vEOS64-lab-<version>.qcow2`, e.g. `vEOS64-lab-4.36.1F.qcow2` |
| Tested with   | 4.36.1F, x86_64, ~620 MiB compressed and 4 GiB raw |
| Also on offer | `Aboot-veos-serial-<version>.iso` — **not needed here** |

The Aboot ISO is the bootloader every other hypervisor pairs with the
image, and it is deliberately unused: its `kexec` into the EOS kernel
does not survive bhyve, so `veos-bhyve.sh` reads the kernel and initrd
straight out of `vEOS-lab.swi` on the image's own flash partition and
boots them with `grub-bhyve`.  Downloading it does no harm, but nothing
will read it.

Nothing else is version-specific by design, but the EOS CLI is: the
assertions parse `show ip pim interface`, `show ip mroute`, `show ip pim
rp detail` and `show ip pim bsr`, and the configuration uses the
`router pim sparse-mode` / `router pim bsr` syntax of EOS 4.3x.  A much
older or newer release may want the parsers in `eos_*()` adjusting.

This is the only test that puts a second implementation on the wire.
Everything else here has pimd at both ends of every exchange, which
answers "does pimd still do what it did yesterday" and never "does pimd
do what the RFC says".  Bootstrap and Candidate-RP-Advertisement are the
worst case: `src/pim_proto.c` both writes and reads them, and nothing
else ever has.

Two pimd routers run in vnet jails and an Arista vEOS runs under bhyve
between them, over host bridges — one end of each middle link is a bhyve
tap and the other is a jail, and a bridge is the only thing that joins
the two.  What the Arista believes is read over eAPI, so those
assertions are the switch's own view of the exchange rather than an
inference from pimd's logs.

The two scenarios are each other's mirror, and running both is the
point: a parser that is wrong in the same way as its encoder passes one
and fails the other.

| Scenario     | Time | Roles                                      | What it covers |
|--------------|------|---------------------------------------------|------------------|
| `arista-rp`  | ~3m  | Arista is BSR, RP and the router in the middle; R1 is first hop, R3 last hop. | pimd parses a Bootstrap and Candidate-RP-Advertisement written by EOS; EOS has to believe pimd's (\*,G) Join and decapsulate its Register.  DR election is asserted on two links and from both sides, pimd losing one and winning the other. |
| `pimd-rp`    | ~4m  | R1 is BSR and RP; the Arista is first *and* last hop router, for a LAN of its own. | The mirror of the above.  EOS parses pimd's Bootstrap — address, priority and hash mask length asserted separately — R3 has to learn the same RP set *through* the Arista, and pimd has to believe an EOS-built Join and decapsulate an EOS Register, then get off the register vif and have its Register-Stop honoured. |
| `assert-lan` | ~12m | Three PIM routers share one segment: pimd's R3 and the Arista contend on it, pimd's R5 is downstream. | The assert election, on a topology of its own.  See below — written to reach code no other test executes, and it found the deviation that kept it from doing so. |

### `assert-lan`: what it was for, and what it found

pimd's assert metric preference is a configured constant, not the
routing protocol's administrative distance (deviation **M4** in
`doc/rfc7761-compliance.md`; the metric beside it is the routing
table's since the same entry's other half was fixed).  Between two
pimds every router on a LAN therefore advertises the *same* preference,
and until `shared-lan` started moving route metrics around they
advertised the same metric too: `compare_metrics()` tied and the
address decided, so the two metric comparisons RFC 7761 sec. 4.6.1 runs
before that tiebreak were dead code in every test here, and the
encoding of those fields (sec. 4.9.6) was only ever read by the code
that wrote it.  EOS fills both from its own RIB, so this is still the
one LAN in the tree where the preference can hold unequal numbers.

They did not at first, and that was the finding.  pimd evaluated SPTbit
only when an upcall reached `update_sptbit()` (`src/route.c`) rather
than on every data packet as sec. 4.2 asks, so R3 never reached the
shortest path tree here and kept asserting from `(*,G)` state with the
RPT bit set, which sec. 4.6.1 compares before either metric.  That was
deviation **M10**, and this scenario is what turned it up.  It is fixed
— `age_routes()` re-runs the check for as long as data is arriving — and
the assertion that reported it stays, as a tripwire: it goes back to
**KNOWN** if R3 ever stops reaching the tree.

So all four sub-cases below compare what they were written to compare:

| Sub-case      | Decided by | Winner | Today |
|---------------|------------|--------|-------|
| `pimd-wins`   | `metric_preference`, pimd's lower | pimd | asserted |
| `arista-wins` | `metric_preference`, the Arista's lower | Arista | asserted |
| `tiebreak`    | all three equal, so the address | Arista (higher) | asserted |
| `rpt-bit`     | `rpt_bit_flag`, with pimd given the *better* preference so only the bit can decide | Arista | asserted |

`rpt-bit` is the one that needs no SPT: it wants pimd held on the shared
tree, which `spt-threshold infinity` on both pimd routers does, and the
Arista has to win on the bit despite pimd advertising the better
preference.

What the scenario asserts, then, is DR and IGMP querier election on a
segment shared with a foreign implementation (won by different routers,
agreed by both ends), the RP set learned through it, all four sub-cases
of the election, and M3 as a known deviation.

Two further cases cover what a conformant peer does that another pimd
never would, both for deviation **M3**:

- **AssertCancel** (sec. 4.6.4).  The winner sends an Assert with an
  infinite metric when it stops forwarding, so losers return to NoInfo
  at once.  pimd never sends one, so its *receive* path for one has
  never had an input in any other test; here the Arista sends it and
  pimd is asked to act.
- **Winner never resends** (sec. 4.6.1).  The winner should rearm at
  `Assert_Time - Assert_Override_Interval` and resend.  pimd arms
  nothing, so at `Assert_Time` the Arista returns to NoInfo, resumes
  forwarding, and the LAN carries every packet twice until pimd notices
  the duplicate and asserts afresh.

The second one is why the scenario is slow, and why it polls across the
whole `Assert_Time` crossing instead of sampling once at the end: the
re-election takes one data packet, so a single late reading finds the
Arista off the LAN again and is indistinguishable from a winner that
refreshed properly.  The deviation is the *window*, not the state either
side of it.  `AL_SKIP_RESEND=yes` leaves this case out of a quick run.

ED6 hangs off R3 so that R3 is a last hop router in its own right.  That
is what makes the metric sub-cases readable: R3 plainly meets the
sec. 4.2 conditions — traffic on `RPF_interface(S)`, a non-empty
outgoing list, `RPF'(S,G) == RPF'(*,G)` — and reaches the tree off its
own traffic rather than waiting for an (S,G) Join from R5.  Without it
the contested LAN is R3's only outgoing interface, and losing an assert
empties the list, which leaves `JoinDesired(S,G)` false and no way back
onto the tree — M10 tangled up with M3.

Requirements, on top of the vnet jail lab's: `bhyve` with a VIMAGE
kernel, `sysutils/grub2-bhyve`, `emulators/qemu-tools`,
`sysutils/e2fsprogs`, `python3` (eAPI is JSON), and the image named by
`-i` above.

`-s SLOT` and `-j JOBS` work as they do in the vnet jail lab, and name
the same things apart plus the taps, the bhyve VM (`veos2`) and the
management subnet eAPI is reached over (`172.20.2.0/24`).  What bounds
`-j` here is not cores: each scenario boots a vEOS of its own, 4 GiB of
guest memory and a converted 4 GiB disk apiece.

`lab.sh` must not be up **in the same slot** — the two labs use
the same 10.0.0.0/8 addresses inside their jails, and `check_req()` says
so on startup — but another slot of it may be, and
`net.inet.ip.mcast.loop` is shared between the two labs the same way it
is shared between slots.

### The VM runner

`veos-bhyve.sh` boots the vEOS and knows nothing about PIM.  The
interoperability lab drives it, and it is useful on its own:

    V=./test/veos-bhyve.sh
    Q=~/vEOS64-lab-4.36.1F.qcow2

    sudo $V -q $Q inject startup-config      # write it onto the guest flash
    sudo $V -q $Q -t tap100:br0 -D start     # boot it detached
    sudo $V console                          # attach to the console
    sudo $V cli 'show ip pim neighbor'       # or ask it over eAPI
    sudo $V -q $Q cloudinit startup-config   # the config-drive way instead
    sudo $V stop

It is `bash`, not `sh`, and every subcommand needs root.  `-q` names the
image and is needed only by the three that touch the disk — `start`,
`inject` and `cloudinit`; `stop`, `console`, `status` and `cli` do not
care where it lives.

`-n` names the VM, and several can run at once: everything belonging to
one — the raw disk converted from the qcow2, the kernel and initrd taken
out of it, the grub files, the console device, the pid file — is kept in
`$WORK/<name>`, or named after it.  Two guests cannot share a disk image
(each writes its own startup-config onto the flash, and bhyve opens it
read-write), so a new VM name converts a 4 GiB image of its own on first
boot.  A tree converted by an older version of the script has an unused
`~/veos-bhyve/<image>.raw` one level up, and can delete it.

Its header documents what booting a vEOS under bhyve actually takes, all
of it learned the hard way: the disk holds no bootloader and the kexec
Aboot would do does not survive bhyve, so the kernel and initrd are
loaded out of the SWI by `grub-bhyve`; the initrd's `flashrom` probe
faults the VM and is stubbed out; bhyve exits when the guest reboots, so
the VM runs in a restart loop; and a fresh image boots into Zero Touch
Provisioning, out of which there are two ways — a `startup-config`
written onto the guest ext4 with `debugfs`, or the vendor's
`ARISTA_CONFIG_DRIVE` day0 path, which does work under bhyve once
`EosCloudInit` is told which platform it is on.


Which suite sees what
---------------------

| | Linux suite | vnet jail lab | vEOS lab |
|---|---|---|---|
| Runs in `make check`        | yes | no  | no  |
| Unicast RPF lookups         | `netlink.c` | `routesock.c` | `routesock.c` |
| Kernel glue                 | Linux `kern.c` | BSD `kern.c` | BSD `kern.c` |
| Unicast routing             | OSPF, via bird | static | static |
| Several PIM routers per link| `shared.sh`, `pod.sh` | `shared-lan*` | `assert-lan` |
| Assert metrics that differ  | no | no | `assert-lan` |
| Point-to-point vifs         | no | `gif-tunnel*` | no |
| Interfaces changing at runtime | no | `ifgone`, `renumber` | no |
| A foreign implementation    | no | no | yes |

A change to `src/pim_proto.c` or `src/route.c` wants at least the Linux
suite and the vnet jail lab.  A change to how a message is *encoded* —
Bootstrap, Candidate-RP-Advertisement, Join/Prune, Register, Assert —
wants the vEOS lab too, because it is the only one that can tell a wrong
encoding from a matching pair of wrong ones.

[arista-dl]: https://www.arista.com/en/support/software-download
[185]: https://github.com/troglobit/pimd/issues/185
[211]: https://github.com/troglobit/pimd/issues/211
[218]: https://github.com/troglobit/pimd/issues/218
[243]: https://github.com/troglobit/pimd/issues/243
[251]: https://github.com/troglobit/pimd/issues/251
