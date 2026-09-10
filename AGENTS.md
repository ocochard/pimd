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
`--enable-kernel-encap` / `--enable-kernel-mfc` (patched BSD kernels only).

CI (`.github/workflows/build.yml`) builds with both gcc and clang using
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

`test/freebsd-lab.sh` is the FreeBSD counterpart and is deliberately **not** in `TESTS`: it needs
vnet jails, root and `ip_mroute.ko` (plus `if_bridge.ko` for `shared-lan`), and it drives the
`routesock.c` and `kern.c` BSD branches the Linux suite can never reach. `run all` walks its
scenarios (`rpt`, `keepalive`, `rp-lasthop`, `gif-tunnel`, `gif-tunnel-staticrp`, `shared-lan`,
`shared-lan-spt`); see the script header for the topologies and which upstream issue each one pins
down. The two `shared-lan*` ones are the only ones with several PIM routers on a link, so DR
election, IGMP querier election and the assert election only ever run there. `shared-lan-spt`
reports a known deviation: pimd asserts with the RPT bit clear for a group it only has (\*,G)
state for, where RFC 7761 4.6.1 requires it set. Assertions that reproduce a deviation report
`KNOWN` through `xfail()` instead of failing the run, and turn into an `ok` once pimd is fixed.

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
