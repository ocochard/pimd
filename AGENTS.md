# AGENTS.md

This file provides guidance to AI tools when working with code in this repository.

## Project

pimd is a PIM-SM/SSM multicast routing daemon (RFC 7761/4602/5059) for UNIX, plus the `pimctl` client.
Upstream: https://github.com/troglobit/pimd. IPv4 only. Version 3.0-beta1 (`configure.ac`).

The specs themselves are checked into `doc/`, so check behaviour against them rather than from
memory: `rfc7761.txt` is the current PIM-SM standard (STD 83) and the one to cite, `rfc4601.txt`
is the version it obsoletes, `rfc2362.txt` the experimental one much of this code was originally
written to and which several comments still reference by section number, plus `rfc4602.txt` and
`rfc5059.txt` (BSR). Section numbering differs between them, so name the RFC with the section.

## Build

GNU autotools, `configure` and `Makefile.in` are generated, not in git:

```sh
./autogen.sh                                  # needs autoconf + automake
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
make                                          # `make V=1` for full command lines
```

Useful configure flags: `--enable-test` (build `test/` subdir),
`--with-max-vifs=NUM` (must match kernel `MAXVIFS`), `--disable-exit-on-error`,
`--enable-netlink` (RPF lookups over `netlink(4)` rather than the routing socket; implied
on Linux, needs FreeBSD 13.2 or later elsewhere),
`--enable-kernel-encap` / `--enable-kernel-mfc` (patched BSD kernels only).

CI (`.github/workflows/ci-linux.yml`) builds with both gcc and clang using
`./configure --prefix= --enable-test`, then `make check`.

## Tests

Automake test suite in `test/`, all shell scripts driven by `TESTS_ENVIRONMENT = unshare -mrun`.
They are **Linux-only** (network namespaces, veth, bridges) and need root plus `ethtool`, `tshark`,
and `bird` (OSPF, for the unicast RPF tree). Missing deps make a test SKIP (exit 77), not fail.

```sh
make check                       # run all, or: make check || cat test/test-suite.log
make check TESTS=rp.sh           # single test (from test/ or top dir)
```

Each script builds a router topology (ASCII diagram in its header) from `test/lib.sh` helpers
(`topo()`, `ifsetup()`, `emitter()`/`collect()` around the `mping` tool built from `test/mping.c`),
starts one `pimd` per namespace and asserts on forwarded traffic. Topologies: `single.sh` (one
router), `two.sh`/`three.sh` (chains), `rp.sh` (RP + SPT switchover), `shared.sh`, `pod.sh`
(redundant paths). Set `DEBUG="-l debug -d all"` at the top of a script to get pimd logs and
runtime `pimctl` dumps.

`test/pimsend.c` is the PIM-socket counterpart of `test/igmpv3.c`: it builds one PIM
message of any type, with every field that can be got wrong exposed as an option (version,
type nibble, checksum, group and source mask lengths, address family and encoding type, the
B and Z bits, holdtime), sends it once and exits. Most of `doc/rfc7761-compliance.md` cannot
be reproduced by a lab of pimds at all -- two pimds share one reading of the wire, so a field
pimd encodes wrongly it also decodes wrongly and the lab stays green -- and this is the way
past that. The `crafted` scenario is its first user; write the positive control beside every
"was it refused?" assertion, since a parser that refuses everything passes all of them.

`ssm.sh` is the exception to "asserts on forwarded traffic": it asserts on the IGMPv3 (S,G)
membership state one router holds, and drives it with `test/igmpv3.c`, which sends one membership
report and exits. Use that tool, not a kernel join, whenever a test needs a router to age a
membership out: a kernel that joined a group answers every query afterwards, so the membership
never expires while the emulated device is on the LAN.

`test/freebsd-lab.sh` is the FreeBSD counterpart and is deliberately **not** in `TESTS`: it needs
vnet jails, root and `ip_mroute.ko` (plus `if_bridge.ko` for the shared segment scenarios), and it drives the
`routesock.c` and `kern.c` BSD branches the Linux suite can never reach. `NETLINK=yes` points
it at a `--enable-netlink` build instead, so the same scenarios run over `netlink.c` on FreeBSD;
it asks `pimctl show status` which backend the daemon has rather than trust the tree. `run all` walks its
scenarios (`rpt`, `keepalive`, `rp-lasthop`, `rp-offpath`, `gif-tunnel`, `gif-tunnel-staticrp`,
`shared-lan`, `shared-lan-spt`, `assert-recover`, `ssm`, `ssm-range`, `alias`, `ifgone`,
`renumber`, `register-filter`, `crafted`, `static-rp`); see the script
header for the topologies and which upstream issue each one pins down. `-s SLOT` (0-31) puts every
host-visible name the lab creates -- jails, epairs, bridges, interface group, work directory -- in a
namespace of its own, so several labs run side by side, and `-j JOBS` runs that many scenarios at
once, a slot each (measured on 16 cores: `-j 4 run all` 4m35s, `-j 14` 4m11s, against the ~31
minutes the scenarios add up to sequentially; `keepalive` alone is a 4 minute floor). The addresses inside
the jails are the same in every slot, `net.inet.ip.mcast.loop` is the one piece of host state they
share, and they hold it between them under a lock in `/var/run/pimd-lab-mcastloop`, last one out
restoring it -- `freebsd-interop.sh` counts in the same place. `shared-lan`,
`shared-lan-spt` and `assert-recover` are one topology and the only one with several PIM routers on
a link, so DR election, IGMP querier election and the assert election only ever run there
(`shared-lan` is also the only one that gives two routers different
route metrics, with `route change -metric`, so it is the one place an assert election is decided by
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
address, reached through the Hello Address List of RFC 7761 sec. 4.3.4, `ifgone` and `renumber` the only ones about what pimd does
when an interface it has a VIF on changes underneath it -- destroyed in the first, given a new
address in the second -- `crafted` the only one whose messages pimd did not build, driving
`test/pimsend.c` to assert what the parsers refuse -- the whole packet format section of
`doc/rfc7761-compliance.md` (version, destination, address family and encoding type, mask
lengths, the B and Z bits, a 0xffff holdtime, a Null-Register checksum), the two SSM rules
about what arrives (no shared tree for a group in the range, a Register for one answered
rather than dropped), a Bootstrap for the SSM range leaving the RP pimd invents for it
alone, Join suppression and its HoldTime bound (RFC 7761 sec. 4.5.4, the second router
played by pimsend from R2's jail), a longer group range taking over the groups inside it
(RFC 7761 sec. 4.7.1),
the Hello Address List of sec. 4.3.4 parsed from a list pimd did not write,
a unicast Bootstrap from a host that has sent no Hello, RFC 5059's No-Forward bit
(waives the RPF check, is not forwarded on), and `accept-nbr-from`, which R1 runs the whole
scenario with configured so that every other assertion is a soak test of it -- with a positive control beside each,
`static-rp` the only one where a router has an RP of its own configuration beside the BSR's,
and `register-filter` the only one about who an RP will accept a Register
from, `register-accept-from` and RFC 7761 sec. 6.2, which it drives from both sides: a prefix that
does not cover the address the DR registers from and then one that does, told apart by the
Register-Stop and the DR's Register-Suppression timer rather than by the RP's table, which holds
entries for the group either way because the kernel decapsulates before pimd is handed the message.
That last part is A3 of `doc/rfc7761-compliance.md`, and the scenario asserts it rather than working
around it.
Assertions that reproduce a deviation report `KNOWN` through `xfail()` instead of failing the run,
and turn into an `ok` once pimd is fixed; `shared-lan-spt` has this file's only one, for the assert
RPT bit of RFC 7761 4.6.1, and it now reports `ok` -- the deviation it guards was fixed in
`4cb79f1`, so the assertion stays as a tripwire. `test/freebsd-interop.sh` has four more and all
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
  `ok` and stay as tripwires. `AL_SKIP_RESEND=yes` skips the 180s case.

`run all` walks all three. Not in `TESTS`: it needs bhyve and a licensed vEOS-lab image, named with
`-i` (`vEOS64-lab-<version>.qcow2` from arista.com; there is no default path). `-s` and `-j` work as
in `freebsd-lab.sh` and additionally name the taps, the bhyve VM and the management subnet apart;
what bounds `-j` here is a vEOS per scenario, 4G of RAM and a converted 4G disk each. A lab in the
*same* slot of `freebsd-lab.sh` is refused, one in another slot is not.
`test/veos-bhyve.sh` is the VM runner it drives (see its header for how a vEOS boots under bhyve at
all), usable on its own: `start`/`stop`/`console`, `inject` to write a startup-config onto the guest
flash with `debugfs`, `cloudinit` for the vendor `ARISTA_CONFIG_DRIVE` day0 path, and `cli` to run
EOS commands over eAPI. Everything belonging to one VM lives in `$WORK/<name>`, `-n` naming it, so
several guests run at once; sharing one raw disk image, which is what they did before, corrupts it.

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
`timer.c` providing a delta-queue of callbacks aged once per `TIMER_INTERVAL`. All protocol state is
global (declared `extern` in `defs.h`), so ordering of the `init_*()` calls in `main()` matters:
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
reformatting. `pimd` builds with `-W -Wall -Wextra -Wno-unused`; `logit()` is `printf`-format
checked.

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
