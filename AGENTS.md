# AGENTS.md

This file provides guidance to AI tools when working with code in this repository.

## Project

pimd is a PIM-SM/SSM multicast routing daemon (RFC 7761/4602/5059) for UNIX, plus the `pimctl` client.
This repository, https://github.com/ocochard/pimd, is where pimd is maintained; it is a fork of
https://github.com/troglobit/pimd, which has none of the work here, so never send a user, a bug
report or a support question there, and never cite its issue tracker as this project's.
Its old issue numbers are still the right citation for a bug that was reported there, spelled
`troglobit/pimd#NNN` as `src/config.c` and `test/lab.sh` already do.
IPv4 only. Version 3.2-beta1 (`configure.ac`).

The specs themselves are checked into `doc/`, so check behaviour against them rather than from
memory: `rfc7761.txt` is the current PIM-SM standard (STD 83) and the one to cite, `rfc4601.txt`
is the version it obsoletes, `rfc2362.txt` the experimental one much of this code was originally
written to and which several comments still reference by section number, plus `rfc4602.txt` and
`rfc5059.txt` (BSR). Section numbering differs between them, so name the RFC with the section.
For anycast RP: `rfc4610.txt` is anycast RP inside PIM itself, by Registers copied between the RPs,
which is what `anycast-rp` in `pimd.conf` implements; `rfc3618.txt` is MSDP, which pimd does not
implement (its own cross-references to "section 13" and "section 15" mean sec. 10 and sec. 11),
`rfc3446.txt` anycast RP over MSDP, and `rfc4611.txt` the MSDP deployment BCP, where the peer-RPF
relaxations for a network without BGP are.

## Build

GNU autotools, `configure` and `Makefile.in` are generated, not in git:

```sh
./autogen.sh                                  # needs autoconf + automake
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make                                          # `make V=1` for full command lines
```

`configure` probes a set of warning and hardening flags rather than hardcoding one, since this
builds with gcc and clang on four systems: the ones the compiler takes land in `PIMD_CFLAGS` and
`PIMD_LDFLAGS`, which `src/Makefile.am` and `test/Makefile.am` pick up as `AM_CFLAGS` and
`AM_LDFLAGS`, so `pimd`, `pimctl`, the `lib/` replacements and the test tools all get them. The
configure summary prints what was kept. `--disable-hardening` drops the runtime half
(`_FORTIFY_SOURCE`, stack protector, `-ftrivial-auto-var-init=zero`, PIE, RELRO/BIND_NOW), which a
packager may want; `-fno-strict-aliasing` is in that half but is not optional in spirit, since
`pim.c` and `igmp.c` cast the `char *` receive buffers to `struct ip *` and friends on nearly every
path. `--enable-werror` turns the warnings into errors and is off by default -- a tarball built
with `-Werror` stops building on the next compiler, on a machine where nobody can edit the
Makefile -- and the build jobs of both CI workflows pass it.

`src/` builds every object but `main.c` into a static convenience library, `libpimd.a`, and links
`pimd` from that plus `main.c`; nothing about the binary changes, and the fuzz harnesses of
`test/fuzz/` link the daemon's own objects without a second copy of the source list.

Useful configure flags: `--enable-test` (build `test/` subdir),
`--enable-fuzz` (the fuzz harnesses, see Tests below; implies `--enable-test` and
`--disable-exit-on-error`, and adds `-fsanitize=fuzzer-no-link` to the probed flags),
`--with-max-vifs=NUM` (must match kernel `MAXVIFS`), `--disable-exit-on-error`,
`--enable-netlink` (RPF lookups over `netlink(4)` rather than the routing socket; implied
on Linux, needs FreeBSD 13.2 or later elsewhere),
`--enable-kernel-encap` / `--enable-kernel-mfc` (patched BSD kernels only).

CI (`.github/workflows/ci-linux.yml`) builds with both gcc and clang using
`./configure --prefix= --enable-test`, then `make check`.

## Tests

`TESTS` is empty unless the tree was configured `--enable-fuzz`, when it holds one entry, the fuzz
corpus replay of `test/fuzz-corpus.sh`; in an ordinary build `make check` still runs nothing. Every
Linux-only script that was here is a scenario of
`test/lab.sh` now, which asserts the same and more and runs on both systems; the last three went once
`solo` and two steps of `rpt` covered their shape. The labs want real root and named namespaces,
which automake's `unshare -mrun` cannot give, so CI runs `lab.sh` as a job of its own per system.

```sh
make check                       # run all, or: make check || cat test/test-suite.log
make check TESTS=rp.sh           # single test (from test/ or top dir)
```

`make check` builds `mping`, `igmpv3` and `pimsend` (`--enable-test`) and runs no test of its
own outside a fuzz build; the labs compile their own copies of the three when they start.
`DEBUG="-l debug -d all"` at the top of `lab.sh` gets pimd logs and runtime `pimctl` dumps out of
a scenario.

`test/pimsend.c` is the PIM-socket counterpart of `test/igmpv3.c`: it builds one PIM
message of any type, with every field that can be got wrong exposed as an option (version,
type nibble, checksum, group and source mask lengths, address family and encoding type, the
B and Z bits, holdtime), sends it once (or `-c COUNT` times, for a burst) and exits. `-x COUNT`
flips that many bytes of the body instead and computes the checksum afterwards, so the mutant
reaches a parser rather than dying at the checksum test, redrawn per packet under `-c` and drawn
from `-S SEED` so the same flood repeats on either system; `-b FILE` sends the bytes of a file
verbatim, which is how a corpus input or a crasher from `test/fuzz/` goes on the wire, and `-o FILE`
writes the message it would have sent instead of sending it, which needs neither a socket nor root
and is how the seeds of `test/fuzz/corpus/pim/` are built.

Most of `doc/rfc7761-compliance.md` cannot be reproduced by a lab of pimds at all -- two pimds
share one reading of the wire, so a field pimd encodes wrongly it also decodes wrongly and the
lab stays green -- and this is the way
past that. The `crafted` scenario is its first user; write the positive control beside every
"was it refused?" assertion, since a parser that refuses everything passes all of them.

`test/fuzz/` is the in-process half of the same idea, and needs no network, no root and no kernel:
`--enable-fuzz` builds three harnesses, each with a `_replay` twin driven by a `main()` of its own over
files -- which is what `make check` runs over `test/fuzz/corpus/`, so every input a fuzzer found and
every crasher it produced stays asserted everywhere, with no clang and no privileges. The sanitizers
are the verdict: build the tree `-fsanitize=address,undefined` or a run only proves the parsers do
not segfault. `fuzz_config` hands generated bytes to `config_phyints_from_file()` and
`config_vifs_from_file()` a few tens of thousands of times a second. `fuzz_pim` hands one PIM message
to `accept_pim()` and so to the `receive_pim_*()` it dispatches to, some ten thousand a second under
both sanitizers (`fuzz_igmp` seven and a half), reaching about 3600 edges from the seeds in a
minute and 3800 to 3900 over a quarter of an hour on four workers; its input is one message and
nothing else, which is byte for byte what `pimsend -o FILE` writes and `pimsend -b FILE` sends, so a
crasher goes on the wire against a live daemon and a lab mutant that killed one becomes a corpus
entry. What it *cannot* see is the four bytes before the body -- it fixes the checksum up after the
mutation, as `pimsend -x` does, and picks the destination from the type nibble -- so a bad checksum,
a bad version and a wrong destination stay `crafted`'s to assert. `fuzz_igmp` hands one IP packet to
`accept_igmp()`, which is three things behind one entry point: IGMP itself, mtrace (`trace.c`), and
the kernel upcall path of `route.c`, reached with an IP protocol of zero and read as a `struct
igmpmsg` -- deviations V5 and V6 both lived there and both were found by reading, which is the
argument for fuzzing it. Its input is the whole IP packet rather than the message, the protocol byte
and the header length being what `accept_igmp()` reads first; `igmpv3 -o FILE` writes seeds of that
shape and the three upcall seeds are committed as bytes, their layout written down in
`test/fuzz/README.md`.

The router all of them run the parsers inside is `test/fuzz/router.c`, over the addresses of
`test/fuzz/topology.h`, built per input and torn down again: two interfaces, three neighbours, a DR
election this router wins on one link and loses on the other, an RP set with one range of its own and
one a neighbour is the RP for, a BSR candidacy, a (\*,G) and an (S,G), all from a `pimd.conf`
`config.c` itself parses and a prologue of Hellos and Joins the daemon's own receive path handles.
`test/fuzz/mrib.c` answers the RPF lookups from a fixed table of its own -- it defines
`k_req_incoming()`, so neither `netlink.c` nor `routesock.c` is linked and an input answers the same
on every machine. Every part of that state is there because something is unreachable without it, and
the way to tell is the `INITED` line of a hunt, the edges the committed seeds reach before any
mutation: 2651 for `fuzz_pim` and 2828 for `fuzz_igmp`. It was measured, not assumed -- at the
default DR priority this router lost both elections, and `send_pim_register()` and the register half
of `process_cache_miss()` were dead code with nothing reporting it. `FUZZ_DEBUG=1` turns the daemon's
logging back on, which is the other way to tell a harness whose state is right from one that refuses
every message at the first test: both are silent, fast and green. `router.c` also poisons the receive
buffer past the end of each packet, since both buffers are 128K and an over-read otherwise lands in
stale bytes of the same allocation that ASan is happy with -- which is precisely the shape of
deviation V5, and would have been invisible to a hunt of any length. `--enable-fuzz` implies `--disable-exit-on-error`, because `logit(LOG_ERR)` calls
`exit(-1)` and a fuzzer reads that as a crash on the first input pimd refuses, and it puts
`-fsanitize=fuzzer-no-link` in the probed flags so the *daemon's* objects carry the coverage
instrumentation -- without that the harness alone is instrumented and the run explores 7 edges of
`config.c` instead of 730, at full speed, looking healthy. `test/fuzz/README.md` has the recipes;
`test/fuzz/stubs.c` supplies what `main.c` would have defined. Commit crashers into the corpus, not a
hunt's own corpus: the seeds there are the readable ones, one per shape of input, and a full one
rebuilds from them in a quarter of an hour (743 edges of `config.c`, 175 files after `-merge=1`,
measured). A harness must not grow per input either -- the state one input makes goes back before the
next -- and that is measured with `-runs=N` against `-runs=4N`, not assumed: `fuzz_config` leaked the
static RP list of every `rp-address` line that way, 39MB per 600k inputs, and ended a long hunt at
libFuzzer's RSS limit rather than at a bug.

`test/igmpv3.c` sends one IGMPv3 membership report and exits, which is what the `ssm` scenario of
`lab.sh` drives to assert (S,G) membership state rather than forwarded traffic. Use that tool, not a kernel join, whenever a test needs a router to age a
membership out: a kernel that joined a group answers every query afterwards, so the membership
never expires while the emulated device is on the LAN.

`test/lab.sh` is the FreeBSD counterpart (it runs on Linux too, see below) and is deliberately **not** in `TESTS`: it needs
vnet jails, root and `ip_mroute.ko` (plus `if_bridge.ko` for the shared segment scenarios), and it drives the
`routesock.c` and `kern.c` BSD branches the Linux suite can never reach. Its scenarios reach the host
only through the functions of `test/lab-freebsd.sh` (jails, epairs, bridges, addresses, routes, and
the kernel's MFC, vif and membership views), so a check that needs something from the OS gets a
function there rather than an inline `jexec`/`ifconfig`/`netstat`. `test/lab-linux.sh` implements the
same functions over named netns, veth and Linux bridges, picked by `uname -s`, so the same script runs
the same scenarios as root on Linux (not under `make check`); a fact the scenarios assert that differs
by kernel (`LOOPBACK_IF`, `REGISTER_UPCALL`) is a variable there too. `NETLINK=yes` points
it at a `--enable-netlink` build instead, so the same scenarios run over `netlink.c` on FreeBSD;
it asks `pimctl show status` which backend the daemon has rather than trust the tree. `SANITIZE=yes`
does the same for a tree built `-fsanitize=address,undefined` (asking the binary for the runtime) and
fails any scenario whose daemons wrote a sanitizer report, which is how the reload use-after-free of
`c721f76` and the undefined shifts of `8b0c103` were found; leak checking is off unless
`SAN_ASAN_OPTIONS` asks for it, and on Linux alone, LeakSanitizer being Linux only.
`.github/workflows/sanitize.yml` is that run automated, weekly on Linux and in a FreeBSD VM -- the
only sanitizer coverage `routesock.c` and the `kern.c` BSD branches get, the Linux job compiling
`netlink.c` instead -- and by `workflow_dispatch` for a scenario or two by hand.  It configures that
tree `--disable-hardening` and puts `-fno-strict-aliasing` back by hand, since
`-ftrivial-auto-var-init=zero` zeroes precisely the stack residue a short-packet read would show and
`_FORTIFY_SOURCE` wraps what ASan interposes, while the aliasing flag is in that set without being
hardening. `run all` walks its
scenarios (`rpt`, `keepalive`, `rp-lasthop`, `rp-offpath`, `gif-tunnel`, `gif-tunnel-staticrp`,
`shared-lan`, `shared-lan-spt`, `assert-recover`, `ssm`, `ssm-range`, `alias`, `ifnew`, `ifgone`,
`renumber`, `register-filter`, `crafted`, `fuzz`, `static-rp`, `anycast`, `anycast-dr`, `privsep`); see the script
header for the topologies and which upstream issue each one pins down. `keepalive` is also the
only one where a host floods a DR with groups, `local-sg-limit` capping the (S,G) state that makes
(steps 5 and 6: the flood refused at the limit, and the count given back by a reload). `-s SLOT` (0-31) puts every
host-visible name the lab creates -- jails, epairs, bridges, interface group, work directory -- in a
namespace of its own, so several labs run side by side, and `-j JOBS` runs that many scenarios at
once, a slot each (measured on 16 cores: `-j 14 run all` 6m55s, against the half hour and more the scenarios add
up to sequentially; `keepalive` alone is a floor of about 6 minutes). The addresses inside
the jails are the same in every slot, `net.inet.ip.mcast.loop` is the one piece of host state they
share, and they hold it between them under a lock in `/var/run/pimd-lab-mcastloop`, last one out
restoring it -- `freebsd-interop.sh` counts in the same place. `shared-lan`,
`shared-lan-spt` and `assert-recover` are one topology and the only one with several PIM routers on
a link, so DR election, IGMP querier election and the assert election only ever run there
(`shared-lan` is also the only one that gives two routers different
route metrics, with `route change -metric` (FreeBSD 16 and later, step 12 skips itself on older route(8)), so it is the one place an assert election is decided by
the routing table instead of by the addresses, and `assert-recover` is the only one about how a
router *leaves* the assert state rather than how it enters one -- it kills the winner's pimd so the
loser meets a new GenID, then renumbers the winner's interface downwards),
`rp-offpath` is the only one whose topology is not a chain, so it is the only one where a router is
adjacent to the BSR and the RP and where the shared tree and the shortest path tree leave a router by
different interfaces, `ssm` and `ssm-range` are the only ones about IGMP state rather than PIM
forwarding (`ssm-range` moves the SSM range off 232/8 from `pimd.conf` and asserts both halves of
the replacement), `alias` the only one where an interface carries more than one address, so the only
one that reaches the alias branch of `config_vifs_from_kernel()`, the only one whose sender sits
on a subnet the VIF does not own, and the only one where a next hop is a router's secondary
address, reached through the Hello Address List of RFC 7761 sec. 4.3.4, `ifnew`, `ifgone` and
`renumber` the only ones about what pimd does when the interfaces change underneath it -- one
appears in the first, and has to become a VIF, take the settings of a `phyint` line written before
it existed, and keep its slot when it goes and comes back; one it has a VIF on is destroyed in the
second and given a new address in the third -- `crafted` the only one whose messages pimd did not build, driving
`test/pimsend.c` to assert what the parsers refuse -- the whole packet format section of
`doc/rfc7761-compliance.md` (version, destination, address family and encoding type, mask
lengths, the B and Z bits, a 0xffff holdtime, a Null-Register checksum), the two SSM rules
about what arrives (no shared tree for a group in the range, a Register for one answered
rather than dropped), a Bootstrap for the SSM range leaving the RP pimd invents for it
alone, Join suppression and its HoldTime bound (RFC 7761 sec. 4.5.4, the second router
played by pimsend from R2's jail), the override Join to that router's Prune and the
triggered Hello to a new neighbor, and R1's Prune-Pending Timer on its LAN (all timed over
several trials off the routers' logs),
a longer group range taking over the groups inside it (RFC 7761 sec. 4.7.1),
the (S,G,rpt) machines of sec. 4.5.3 and 4.5.7 (a Prune(S,G,rpt) leaving another router's
Join(S,G) alone, waiting out the override interval, lifted by a Join(S,G,rpt) or a Join(*,G)
that does not carry it, and R1's own override Join(S,G,rpt) upstream, and `rpt-prune-limit` capping the (S,G) state those
Prunes make, step 13b),
the Hello Address List of sec. 4.3.4 parsed from a list pimd did not write,
a unicast Bootstrap from a host that has sent no Hello, RFC 5059's No-Forward bit
(waives the RPF check, is not forwarded on), and `accept-nbr-from`, which R1 runs the whole
scenario with configured so that every other assertion is a soak test of it -- with a positive control beside each,
`fuzz` the same sender and topology with messages that are wrong in no particular way instead: five
hundred mutants of every type, `pimsend -x` flipping bytes of the body and checksumming afterwards
so they reach a parser, from a fixed seed so a failure can be sent again, and it is the only test
that puts that question to a *running* daemon rather than to a harness -- neighbours, an RP set, a
kernel MFC and a register vif behind the parser -- with the sanitizers as the verdict under
`SANITIZE=yes` and liveness, neighbour and RP-set state as the verdict without them; which RP it
holds afterwards is deliberately not asserted, a mutant Bootstrap that stays valid being a BSR
takeover and RFC 7761 sec. 4.7 working rather than a bug,
`static-rp` the only one where a router has an RP of its own configuration beside the BSR's,
`anycast` the only one where two routers are the RP for the same address, an RFC 4610
Anycast-RP set on `lo0` of R2 and R3 that copy each other Registers (Null-Registers on FreeBSD,
whose kernel hands pimd only the headers of a data Register), which also asserts the copy budget with a
`pimsend -c` burst (step 10) and `register-sg-limit` refusing Register-made state, given back by a reload
(step 11), and `anycast-dr` the same set moved so that R1 is the RP and the DR of the source at once and
has to register it to R3 itself, and must not let a member's Register-Stop arm the suppression timer of
an entry it is not registering (step 9),
`privsep` the only one about the daemon's own two halves rather than about PIM: that the
process holding root is not the one parsing the wire, that `pimctl show status` and the kernel
agree on which user, which sandbox (`seccomp` on Linux, `none` on the BSDs -- Capsicum refuses
every `sendto()` carrying a destination, so pimd cannot use it) and which `chroot()` -- compared
against what the kernel resolves the child's `/` to, `proc_root()` in the two OS files -- that a
SIGHUP to the PID file,
which names the privileged parent, rebuilds every VIF out of descriptors the parent hands back,
and, as its control, that `--no-privsep` is one root process that forwards just as well.  It is
on the three router chain and not on `solo` deliberately: a sandbox that forbids sending leaves a
lone router electing itself BSR and RP, answering `pimctl` and sending nothing, which is exactly
how the Capsicum attempt passed `solo` and failed everything with a neighbour in it.
`register-filter` is the only one about who an RP will accept a Register
from, `register-accept-from` and RFC 7761 sec. 6.2, which it drives from both sides: a prefix that
does not cover the address the DR registers from and then one that does, told apart by the
Register-Stop and the DR's Register-Suppression timer rather than by the RP's table, which holds
entries for the group either way because the kernel decapsulates before pimd is handed the message.
That last part is A3 of `doc/rfc7761-compliance.md`, and the scenario asserts it rather than working
around it.
Assertions that reproduce a deviation report `KNOWN` through `xfail()` instead of failing the run,
and turn into an `ok` once pimd is fixed; `shared-lan-spt` has one, for the assert
RPT bit of RFC 7761 4.6.1, and it now reports `ok` -- the deviation it guards was fixed in
`4cb79f1`, so the assertion stays as a tripwire. `crafted` has six more, steps 10, 11 and 13, for
deviation M1, the (S,G,rpt) state, and they report `ok` the same way. `test/freebsd-interop.sh` has four more and all
four report `ok` as well: two for deviation M3, now that the assert state is per interface -- an
AssertCancel is acted on and a winner resends before the losers time out -- one for M10, the SPTbit
evaluated per packet rather than only on an upcall, and one for M14, the (S,G) Assert machine
reachable after the shared tree has lost the interface. No `xfail()` in either file is live -- a
`KNOWN` line in a run is a regression, not an expected result.

`doc/rfc7761-compliance.md` is the list these come from: every entry there ends with a `Test:` note
naming what reproduces it, or `none`, so which deviations are covered and which are only written
down is answerable from that file rather than by grepping the labs.

`test/freebsd-interop.sh` is the only test that puts a second PIM implementation on the wire: an
Arista vEOS in bhyve, between two pimd routers in vnet jails. Every other test has pimd on both
ends, so a message pimd encodes wrongly it also decodes wrongly and the run stays green. Its two
scenarios are each other's mirror, and running both is the point -- a parser that is wrong in the
same way as its encoder passes one and fails the other:

- `arista-rp`, the Arista is the BSR, the RP and the router in the middle. pimd parses a Bootstrap
  and Candidate-RP-Advertisement written by EOS, and EOS has to believe pimd's `(*,G)` Join and
  decapsulate its Register. Also asserts DR election on two links from both sides, with pimd losing
  one and winning the other.
- `pimd-rp`, the roles reversed: R1 is the BSR and RP, the Arista is the first and last hop router
  for a LAN of its own. EOS parses pimd's Bootstrap (address, priority and hash mask length are
  asserted separately), R3 has to learn the same RP set *through* the Arista, and pimd has to
  believe an EOS-built Join and decapsulate an EOS Register -- then get off the register vif and
  have its Register-Stop honoured, measured over a second stream once the tree is up.
- `assert-lan`, the assert election, on a topology of its own: three PIM routers on one segment,
  pimd's R3 and the Arista contending on it. Written to compare *unequal* assert metrics, which no
  other test could then -- pimd advertised two configured constants rather than the MRIB's numbers
  (deviation M4), so between two pimds they always tied and the address decided, leaving the two
  comparisons RFC 7761 4.6.1 makes first as dead code. Half of that is fixed: the metric is the
  routing table's now, and `shared-lan` moves it, but the preference is still `distance` from
  `pimd.conf` and the Arista is the only router here that derives one. Getting that far took fixing deviation M10, which this
  scenario turned up: pimd evaluated SPTbit only when an upcall reached `update_sptbit()` rather
  than per packet as sec. 4.2 asks, so R3 asserted from `(*,G)` with the RPT bit set and its metric
  was never reached. The assertion that reported it stays as a tripwire. What the scenario asserts
  is DR and IGMP querier election against a foreign implementation, the RP set learned through it,
  all four sub-cases of the election -- the three metric ones and `rpt-bit`, where the Arista must
  win on the bit despite pimd holding the better preference -- and the two halves of M3, an
  AssertCancel from the Arista and pimd holding the LAN past Assert_Time, both of which now report
  `ok` and stay as tripwires. `AL_SKIP_RESEND=yes` skips the 180s case, which also times pimd's
  resend against the 177 seconds of RFC 7761 sec. 4.6.1.

- `rpt-override`, whether the Arista honours pimd's Join(S,G,rpt): `arista-rp`'s chain plus X3, a
  pimsend box on the link between the Arista and R3, which is held on the shared tree with
  `spt-threshold infinity`. X3 prunes the source off the shared tree at the Arista and R3 has to
  override inside the J/P_Override_Interval. Read off R3's kernel packet counters and a tcpdump
  capture on X3 of what R3 sent, with a control first: R3's pimd stopped with SIGSTOP, so the Prune
  goes unanswered and the source has to stop, then continued, so its override has to bring the
  source back.

- `anycast`, an RFC 4610 Anycast-RP set of the Arista and R3 on `pimd-rp`'s topology, asserted in both
  directions and each exchange beside its control: EOS's copy and its own-source Register believed by
  pimd, pimd's own-source Register (and its Register-Stop) and its data and Null-Register copies
  believed by EOS. EOS's member address has to be a /32 on a loopback (`Loopback2` here): with an
  interface address EOS takes the set and never acts on it, which a first version of this scenario
  mistook for EOS not implementing half of RFC 4610.

`run all` walks all five. Not in `TESTS`: it needs bhyve and a licensed vEOS-lab image, named with
`-i` (`vEOS64-lab-<version>.qcow2` from arista.com; there is no default path). `-s` and `-j` work as
in `lab.sh` and additionally name the taps, the bhyve VM and the management subnet apart;
what bounds `-j` here is a vEOS per scenario, 4G of RAM and a converted 4G disk each. A lab in the
*same* slot of `lab.sh` is refused, one in another slot is not.
`test/veos-bhyve.sh` is the VM runner it drives (see its header for how a vEOS boots under bhyve at
all), usable on its own: `start`/`stop`/`console`, `inject` to write a startup-config onto the guest
flash with `debugfs`, `cloudinit` for the vendor `ARISTA_CONFIG_DRIVE` day0 path, and `cli` to run
EOS commands over eAPI. Everything belonging to one VM lives in `$WORK/<name>`, `-n` naming it, so
several guests run at once; sharing one raw disk image, which is what they did before, corrupts it.

Which lines of the daemon any of that reaches is measured rather than read: `--enable-coverage`
puts `--coverage` in the probed flags (and drops the hardening set, `_FORTIFY_SOURCE` wanting the
optimiser that the `-O0` a line count needs takes away), `COVERAGE=yes` runs the `lab.sh`
scenarios against such a build, and `test/coverage.sh reset` / `report` turns the counters into a
table sorted by unreached lines plus the uncovered ranges per file. Two builds and two tables, not
one number: `--enable-fuzz` implies `--disable-exit-on-error`, so the corpus replay of `make
check` cannot share a tree with the labs, which assert against a daemon that exits on
`logit(LOG_ERR)`. `.github/workflows/coverage.yml` runs both weekly and puts the tables in the job
summary; nothing fails on a number. Read `doc/README-coverage.md` before quoting one, because
three things are invisible to it: the unprivileged half of a separated daemon (a `.gcda` is an
`open(2)` the seccomp filter kills and a path the `chroot()` removed, which is why `COVERAGE=yes`
runs the scenarios `--no-privsep` and why the `privsep` scenario, which keeps the split, reports
only its parent), a daemon SIGKILLed on purpose (`restart_pimd()`, for the GenID), and whichever
of `routesock.c` and `netlink.c` the measuring host does not compile.

## Running

Needs root and a multicast-capable kernel (`CONFIG_IP_MROUTE`/`CONFIG_IP_PIMSM_V2` on Linux,
`options MROUTING`/`options PIM` on BSD). Config defaults to `/etc/pimd.conf`.

```sh
sudo ./src/pimd -n -s -l debug -d igmp,pim_jp,kernel,pim_register -f ./pimd.conf
sudo ./src/pimctl show pim            # or: show mrt / show rp / show interface / show neighbor
```

`-i IDENT` changes syslog name, `.conf`, PID and socket file names all at once, for running
several instances (one per `-t TABLE_ID` on Linux). `pimctl -u FILE` picks a non-default socket.
`doc/README-debug.md` has the kernel-state checklist (`/proc/net/ip_mr_vif`, `ip_mr_cache`,
`netstat -gn`).

## Architecture

Single-threaded, single process. `main.c` runs a `select()` loop over file descriptors registered
via `register_input_handler()` (IGMP socket, PIM socket, routing socket/netlink, pimctl IPC), with
`timer.c` providing a delta-queue of callbacks in milliseconds on the monotonic clock; `timer()` in
`main.c` re-arms itself every `TIMER_INTERVAL` to age most protocol state, while the Join,
Prune-Pending and Assert Timers (deadlines acted on by `route_timers_run()` in `route.c`) and the
triggered Hello schedule callouts of their own. All protocol state is global (declared `extern` in `defs.h`), so ordering of the `init_*()` calls in `main()` matters:
`init_vifs()` before `init_rp_and_bsr()` / `add_static_rp()`. `restart()` (SIGHUP, `pimctl restart`)
tears the same state down and rebuilds it in that order; state added anywhere must be reset there
too, or it leaks or goes stale across a reload.

Layers, roughly bottom-up:

- **Kernel/OS glue.** `kern.c` wraps every `setsockopt`/`MRT_*` call (add/del vif, add/change MFC,
  counters). `netlink.c` (Linux) and `routesock.c` (BSD) both implement `init_routesock()` and
  `k_req_incoming()` — the unicast RPF lookup PIM depends on; only one is compiled in, selected by
  the `LINUX`/`BSD` automake conditionals in `src/Makefile.am`. `include/<os>/` holds fallback
  kernel headers for old systems.
- **Interfaces (vifs).** `vif.h`'s `struct uvif` is one virtual interface; the `uvifs[MAXVIFS]`
  array indexed by `vifi_t` is the universal handle passed around the protocol code, and interface
  sets are bitmaps (`PIMD_VIFM_*`). `config.c` populates it from `getifaddrs()` (`config_vifs_from_kernel()`)
  then applies `pimd.conf` (`config_vifs_from_file()`, one `parse_*()` per keyword). `vif.c` starts/stops
  vifs, maintains the register vif, and ages neighbors/queriers.
- **Packet I/O.** `igmp.c` and `pim.c` own the raw sockets, receive buffers, checksums and
  fragmentation, and dispatch to the protocol handlers. `inet.c` has address helpers, including the
  `inet_fmt()`-into-`s1..s4` static-buffer idiom used all over the logs.
- **Protocol state machines.** `pim_proto.c` (the largest file) implements one
  `receive_pim_*()`/`send_pim_*()` pair per message type: hello/DR election, register and
  register-stop, join/prune (with the `build_jp_message_t` per-neighbor message builder and
  `add_jp_entry()`), assert, bootstrap, and cand-RP-adv. `igmp_proto.c` handles IGMPv1/v2/v3
  membership, querier election and per-group timers.
- **Multicast routing table.** `mrt.c` owns the entry graph: `srcentry_t` (source, or RP — same
  struct aliased as `rpentry_t`) and `grpentry_t` lists, each `mrtentry_t` linked into both a source
  list and a group list, with `MRTF_*` flags distinguishing (S,G), (\*,G), (\*,\*,RP) and kernel-cache
  mirrors. `find_route(src, grp, flags, create)` is the single lookup/allocation entry point.
- **Forwarding decisions.** `route.c` reacts to kernel upcalls (`process_kernel_call()` →
  cache-miss / wrong-iif), computes incoming interface (`set_incoming()`) and outgoing interface sets
  (`calc_oifs()` folds `joined_oifs`, `pruned_oifs`, `asserted_oifs`, `leaves`), pushes changes down
  through `change_interfaces()`, and handles the RPT→SPT switch (`check_spt_threshold()`).
- **RP/BSR.** `rp.c` keeps the cand-RP list and group-mask list, the RP hash (`rp_match()`), BSR
  timers, and remapping of groups when the RP set changes.
- **Introspection.** `ipc.c` is a UNIX-socket server: `cmds[]` maps textual `pimctl` commands to
  `show_*()` functions that print to a `FILE *`. `pimctl.c` is the standalone client. `debug.c`
  holds `logit()`, the debug-subsystem bitmask (`-d`) and the compat `show compat` dumps.
  Adding a `pimctl` command means adding an `IPC_*` enum value, a `cmds[]` row and a dispatch case.
- `dvmrp_proto.c` and `trace.c` are legacy DVMRP/mtrace interop stubs.

`lib/` holds fallback implementations (`strlcpy`, `strlcat`, `strtonum`, `pidfile`, `tempfile`,
`utimensat`) pulled in via `AC_REPLACE_FUNCS` only when libc lacks them — do not call them
conditionally, just use them.

## Conventions

Old C code with a deliberately preserved style (see `.github/CONTRIBUTING.md`): four spaces for the
first indent level, tabs beyond that, `case` indented inside `switch`, ~100 column lines, Emacs
`indent-tabs-mode: t` footer at the bottom of each file. Match the surrounding file rather than
reformatting. The warning set is the one `configure` probes (see Build above); `logit()` is
`printf`-format checked. Anything file-local is `static`, and what crosses a file is declared in
`src/defs.h` rather than by an `extern` written out again in each user -- `-Wmissing-prototypes`
and `-Wmissing-variable-declarations` are in that set and CI builds `--enable-werror`, so a new
non-static symbol without a header declaration stops the build.

Portability matters: Linux, FreeBSD, NetBSD and DragonFly are all supported targets, so guard
OS-specific code the way `defs.h` and `src/Makefile.am` already do rather than assuming Linux.

User-visible changes belong in the `[UNRELEASED]` section of `ChangeLog.md`; config keywords and
CLI flags are documented in `man/pimd.conf.5`, `man/pimd.8`, `man/pimctl.8` and the sample
`pimd.conf`, which need updating in the same change.

## Security review

`doc/security-review-prompt.md` is a review prompt, not a vulnerability disclosure policy. It covers
memory safety and buffer hygiene, allocation and free paths, integer and conversion hazards, pointer
and data-flow integrity, and input validation, each keyed to CWE and SEI CERT C rules.

Read it in full and follow it — its audit checklist and its report structure — whenever the task is
to audit or security-review C code here, instead of improvising a checklist.

Apply its checklist to your own diff as well, unasked and whatever the task was called, whenever you
write or edit:

- `src/pim_proto.c`, `src/igmp_proto.c`, `src/trace.c`, `src/pim.c`, `src/igmp.c` — the files that
  walk attacker-supplied network buffers, and every `receive_*()` in them;
- anywhere else that does pointer arithmetic over a received buffer, sizes an allocation, or copies
  into a fixed-size one.

Scoping this to the words "audit" and "review" is how `receive_pim_assert()` came to parse 26 bytes
out of a message `pim.c` guarantees only 4 of. It was written, reviewed and committed as a
protocol fix, and the checklist that would have caught it went unread because nobody called the task
security work. The file being touched is the trigger, not the framing of the request.

Four rules this tree wants at the point of writing, ahead of any wider review:

- **Bound before parsing.** A `receive_*()` that reads past the header checks the message length
  first, the way `PIM_JOIN_PRUNE_MINLEN`, `PIM_BOOTSTRAP_MINLEN`, `PIM_CAND_RP_ADV_MINLEN` and
  `PIM_ASSERT_MINLEN` do. Spell the constant as the fields being read rather than as a number, so it
  stays right when the parser changes.
- **A length off the wire bounds nothing by itself.** Lengths and counts taken from a packet are
  attacker input: check them against what is left of the buffer before trusting them, as the group
  loop in `receive_pim_join_prune()` does. Bounds derived from a packet's own header are precisely
  the "unconstrained length" the prompt says to treat as a vulnerability.
- **Copy with the wrappers.** Use `strlcpy()`/`strlcat()`/`strtonum()` from `lib/` rather than
  introducing new bounded copies, and report through `logit()`.
- **Remediated code still follows the conventions above.** Keep the surrounding indentation style;
  a security fix is not a licence to reformat.

`rules/security.cocci` is the part of that checklist a machine can decide, as twenty-four semantic
patches for Coccinelle's `spatch(1)`. Run it with `rules/run.sh`, which makes two passes and needs
both to hold: every rule has to fire on `rules/control.c`, and `src/` and `lib/` have to stay
silent. The control pass is the point -- `spatch` prints nothing both when a rule finds nothing and
when a rule is broken, so a ruleset never proven to fire proves nothing -- and it is why a rule and
its counter-example go in together, written to look like the code the rule is meant to catch. The
tree is clean, so a line out of the second pass is a regression; each line names the rule that
found it in brackets. `rules/run.sh` exits 77, automake's "skipped", when `spatch` is not
installed, so this is not a build dependency; the `Coccinelle` job of `.github/workflows/ci-linux.yml`
installs it and runs the script. Note that `spatch` honours only the *last* `--dir` on its command
line and silently drops any earlier one, which is why the script walks `src/` and `lib/` one at a
time. Note also that it borrows its regular expressions from whatever it was built against --
`spatch --version` prints which, PCRE on FreeBSD and Str on Debian and Ubuntu -- so a `=~` constraint
must not use alternation: `"^(memcpy|memmove)$"` is a literal name under Str and matches nothing,
which reads exactly like a clean run. The names a rule cares about are lists in its
`@initialize:python@` block, tested in the script; `=~` is for anchored prefixes and character
classes, which both engines read alike.

Four of the rules are about this tree rather than about C, and are the ones worth adding to: a
`receive_pim_*()` that never compares its `len` argument to anything (the `receive_pim_assert()`
bug above, as a pattern), a `uvifs[]` subscript taking a vif index straight from `find_vif_direct()`
or `local_address()` without testing it against `NO_VIF` -- which is `MAXVIFS`, one past the end of
the array -- and the two about the `s1..s4` static buffers of `inet.c`: one call formatting two
addresses into the same one prints the second twice, and `inet_fmt(a, s1, sizeof(s2))` sizes a
buffer by another. The rest are the ordinary C classes, grouped by the section of
`doc/security-review-prompt.md` they come from. The format-string rules went in when nothing in
the build looked for a `printf()` whose format is not a literal; `configure` probes `-Wformat=2`
now, which covers the same ground, and they stay because the probe can drop it -- an older
compiler that will not take the flag still gets the `spatch` pass, which needs no compiler at all.
The mtrace copy fixed in `src/trace.c` was found this way.
