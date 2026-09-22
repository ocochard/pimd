PIM-SM/SSM Multicast Routing for UNIX
=====================================
[![License Badge][]][License] [![Linux Status][]][Linux] [![FreeBSD Status][]][FreeBSD] [![CodeQL Status][]][CodeQL] [![Coverity Status][]][Coverity Scan]

Table of Contents
-----------------

* [Introduction](#introduction)
* [Configuration](#configuration)
* [Running pimd](#running-pimd)
* [Troubleshooting Checklist](#troubleshooting-checklist)
* [Monitoring](#monitoring)
* [Large Setups](#large-setups)
* [Build & Install](#build--install)
* [Building from GIT](#building-from-git)
* [Testing](#testing)
* [Contributing](#contributing)
* [Origin & References](#origin--references)


Introduction
------------

pimd is a lightweight, stand-alone PIM-SM/SSM multicast routing daemon
available under the free [3-clause BSD license][License].  This is the
restored original version from University of Southern California, by
Ahmed Helmy, Rusty Eddy and Pavlin Ivanov Radoslavov.

Development happens in [this GitHub repository][GitHub], which is where
pimd is maintained today.  This is the place to access the GIT sources,
report bugs, and send patches or pull requests.  The project started out
as a fork of [troglobit/pimd][upstream], and tarballs of the 2.x releases
are still on that [releases page][releases page], but that repository has
none of the changes here: its issue tracker is not the one for this pimd,
and support questions about this pimd belong in [our tracker][issues].

The protocol pimd implements is PIM-SM as specified in [RFC 7761][], the
current PIM-SM standard (STD 83), with the Bootstrap Router mechanism of
[RFC 5059][] and Source Specific Multicast of RFC 4607.  Where pimd is
known to disagree with RFC 7761 the disagreement is written down in
[doc/rfc7761-compliance.md][compliance], each entry naming the section it
is measured against and the test that reproduces it, if any.

pimd is developed, built and tested on both FreeBSD and Linux, and CI
covers both: the [Linux][] workflow builds with gcc and clang and runs
the network namespace test suite, the [FreeBSD][] one builds in a VM and
runs the vnet jail lab (see [Testing](#testing)).  On Linux it should
work as-is out of the box on all major distributions.  Other UNIX
variants; NetBSD, DragonFly, and Illumos, may also work, but do not
receive the same amount of testing.

pimd ships with a useful `pimctl` tool, compatible with all PIM daemons
from the same family: pimd, pimd-dense, pim6sd. It can be a very helpful
little tool when debugging and learning PIM setups.  The pimctl API is
documented in the file `src/ipc.c`, in case you want to use `socat` to
talk to pimd over its UNIX domain socket:

    echo "help" |socat - UNIX-CONNECT:/var/run/pimd.sock

For a summary of changes for each release, see the [ChangeLog][].


Configuration
-------------

The configuration is kept in the file `/etc/pimd.conf`, the order of
the statements are in some cases important.

PIM-SM is a designed to be a *protocol independent* multicast routing
protocol.  As such it relies on unicast protocols like, e.g, OSPF, RIP,
or static routing entries to figure out the reverse path to multicast
sources.  This information is necessary in setups with more than one
route between a multicast sender and a receiver to figure out which PIM
router should be the active forwarder.

pimd reads the metric of a route from the kernel routing table, the
route priority on Linux and the per route metric on FreeBSD, so an
Assert election follows the unicast routing table there.  The distance
(preference) that RFC 7761 compares before it is another matter: it
belongs to the routing protocol that provided the route, which the
routing socket does not report, so it has to be configured per active
interface.  If either the distance and/or the metric is missing in an
interface configuration, the following two defaults will be used, the
metric only where the system reports none of its own:

    default-route-distance   <1-255>     default: 101
    default-route-metric     <1-1024>    default: 1024

By default pimd starts up on all interfaces it can find, using the above
defaults.  To configure individual interfaces use:

    phyint <address | ifname> ...

You can reference the interface via either its local IPv4 address or
its name, e.g., eth0.  Some common interface settings are:

   * `disable`: Disable pimd on this interface, i.e., do not send or
     listen for PIM-SM traffic

   * `dr-priority <1-4294967294>`: The DR Priority option, sent in all
     all PIM Hello messages.  Used instead of the IP address in all DR
     elections, if all PIM routers in LAN advertise it.  The higher, the
     better, default 1.

   * `distance <1-255>`: The interface's admin distance value (also
     confusingly referred to as *metric preference* in the RFC) in PIM
     Assert messages.  Used with `metric` to elect the active multicast
     forwarding router.  Defaults to `default-route-distance`

   * `metric <1-1024>`: The cost for traversing this router.  Used with
     the `preference` value above, and only where the kernel reports no
     metric for the route itself.  Defaults to `default-route-metric`

More interface settings are available, see the pimd(8) manual page for
the full details.

The most notable feature of PIM-SM is that multicast is distributed from
so called Rendezvous Points (RP).  Each RP handles distribution of one
or more multicast groups, pimd can be configured to advertise itself as
a candidate RP `rp-candidate`, and request to be static RP `rp-address`
for one or more multicast groups.

    rp-address <address> [<group>[/<LENGTH> | masklen <LENGTH]

The `rp-address` setting is the same as the Cisco `ip pim rp-address`
setting to configure static Rendezvous Points.  The first argument can
be an IPv4 address or a multicast group address.  The default group and
prefix length is 224.0.0.0/16.  Static RP's always have priority 1.

    rp-candidate [address | ifname] [interval <10-16383>] [priority <0-255>] \
                 [group-prefix <group>[</LENGTH> | masklen <LENGTH>]]

The Rendezvous Point candidate, or CRP, setting is the same as the Cisco
`ip pim rp-candidate` setting.  Use it to control which interface that
should be used in RP elections.

   * `address | ifname`: Optional local IPv4 address, or interface name
     to acquire address from.  The default is to use the highest active
     IP address.

   * `interval <10-16383>`: The CRP advertisement interval, in seconds.
     Default: 60 seconds

   * `priority <0-255>`: How important this CRP is compared to others.
     The lower the value here, the more important the CRP.  Like Cisco,
     pimd defaults to priority 0 when this is left out

In the CRP messages sent out by pimd, one or more multicast groups can
be advertised using the following syntax.

    group-prefix <group>[</LENGTH> | masklen <LENGTH>]

Each `group-prefix` setting defines one multicast group and an optional
mask length, which defaults to 16 if left out.  A maximum of 255
multicast group prefix records is possible for the CRP.

To keep track of all Rendezvous Points in a PIM-SM domain there exists a
feature called *Bootstrap Router*.  The elected BSR in a PIM-SM domain
periodically announces the RP set in Bootstrap messages.  For details on
PIM BSR operation, see [RFC 5059][].

    bsr-candidate [address | ifname] [priority <0-255>] [interval <10-26214>]

The configuration of a Candidate BootStrap Router (CBSR) is very similar
to that of CRP.  If either the address or the interface name is left out
`pimd` uses the highest active IP address.  If the priority is omitted,
`pimd` (like Cisco) defaults to priority 0.  If the interval is omitted,
it defaults to the RFC value of 60 seconds.

Groups in the Source Specific Multicast range never use an RP; pimd
builds a source tree for each (S,G) a receiver asks for.  That range is
232.0.0.0/8, from RFC 4607, unless `pimd.conf` says otherwise:

    ssm-range [default | <group>[/<LENGTH> | masklen <LENGTH>]]

As with the Cisco `ip pim ssm range` setting, the ranges given *replace*
the default rather than adding to it, so keeping 232.0.0.0/8 in service
alongside a range of your own takes an explicit `ssm-range default` line.
Several `ssm-range` lines may be given, a range covering the link-local
groups 224.0.0.0/24 is rejected, and `pimctl show status` lists the
ranges in effect.

Note, this changes how a group behaves and not merely how it is named.
Receivers on an SSM group have to name their sources, with IGMPv3, since
an any-source report for such a group is ignored (RFC 4604), and groups
of a default range that has been replaced go back to needing an RP.  All
routers in the domain should agree on the ranges; nothing in PIM
advertises them.

In a PIM-SM domain there can be two, or more, paths from a designated
router (DR) for a multicast sender to reach a receiver.  When receivers
begin joining multicast groups all data is received via the *shared
tree* (RPT) from each Rendezvous Point (RP).  This is often not an
optimal route, so when the volume starts exceeding a configurable
threshold, on either the last-hop router or the RP itself, the router
will attempt to switch to the *shortest path tree* (SPT) from the
multicast source to the receiver.

In versions of pimd prior to 2.2.0 this threshold was confusingly split
in two different settings, one for the DR and one for the RP.  These
settings are still supported, for compatibility reasons and documented
in the man-page, but it is strongly recommended to change to the new
syntax instead:

    spt-threshold [rate <KBPS> | packets <NUM> | infinity] [interval <5-60>]

Only slightly different from the Cisco `ip pim spt-threshold` setting,
pimd can trigger a switch to SPT on a rate or number of packets and you
can also tweak the poll interval.  It's recommended to keep the interval
in the tens of seconds, the default is 100 sec.  The default threshold
is set to zero packets, which will cause a switch over to the SPT after
the first multicast packet is received.


### Example

    # Interface eth0 is disabled, i.e., pimd will not run there.
    phyint eth0 disable

    # On this LAN we have a lower numeric IP than other PIM routers
    # but we want to take care of forwarding all PIM messages.
    phyint eth1 dr-priority 10

    # Partake in BSR elections on eth1
    bsr-candidate eth1

    # Offer to be an RP for all of 224.0.0.0/4
    rp-candidate eth1
    group-prefix 224.0.0.0 masklen 4

    # This is the built-in defaults, switch to SPT on first packet
    spt-threshold packets 0 interval 100


Running pimd
------------

Having set up the configuration file, you are ready to run `pimd`.  As
usual, it is recommended that you start it manually first, to make sure
everything works as expected, before adding it to your system's startup
scripts, with any startup flags it might need.

    pimd [-hnrsv] [-f FILE] [-i NAME] [-d SYS[,SYS...]] [-l LEVEL] [-p FILE] \
         [-t ID] [-u FILE] [-w SEC]

* `-f FILE`: Use the specified configuration file rather than the
  default, `/etc/pimd.conf`
* `-n`: Run in foreground, with logs to stdout (for systemd and finit)
* `-s`: Use syslog, default unless `-n`
* `-d SYS[,SYS...]`: Subsystems to enable debug for when running the
  daemon.  Type `pimd -h` for the full list of subsystems
* `-l LEVEL`: Log level, one of `none`, `err`, `notice`, `info`, or
  `debug`.  Default is `notice`
* `-i NAME`: Identity, see below
* `-p FILE`: File to store the process ID in, default from `-i`
* `-t ID`: Multicast routing table ID, Linux only
* `-u FILE`: Override the `pimctl` UNIX domain socket, default from `-i`
* `-w SEC`: Initial startup delay before probing interfaces
* `-r`: Retry forever if not all configured interfaces are available at
  startup, e.g. wait for a DHCP lease

For the long options, and the remaining ones, see `pimd -h` and the
pimd(8) manual page.

**Example:**

    pimd -f /cfg/pimd.conf

When running multiple instances of pimd, make sure to use the `-i NAME`
argument, otherwise the PID and IPC socket files will be overwritten and
the syslog will also be hard to follow.  Note, `-i` changes the default
`.conf` filename pimd looks for as well, a complete identity change.


### Enabling Debug

Remember to set the correct log level when enabling debug messages,
usually you need `-l debug`, and `-s` to force messages to syslog
when running in the foreground (`-n`).

    pimd -d igmp,jp,kernel,registers -l debug -n -s


## Troubleshooting Checklist

1. Check the TTL of incoming multicast.  Remember, the TTL of the
   multicast stream must be >1 to be routed.  Or rather, `>` than then
   `ttl-threshold` of the inbound `phyint`

2. If you see `Permission denied` in your logs, you are most likely
   having firewall, or SELinux, problems

3. For PIM-SM, make sure you have a Rendezvous-Point (RP) in your
   network.  Check `rp-candidate` (CRP) and `bsr-candidate` (CBSR)
   settings in your `pimd.conf`, or `rp-address` if you prefer the
   static RP approach

4. Check the Linux `rp_filter` setting.  Many Linux systems have the
   "strict" setting enabled, "loose" can work but may cause problems in
   some setups.  We recommend disabling it entirely

5. PIM is protocol *independent* so you must have unicast routeing in
   place already for `pimd` to work.  Use `ping` to verify connectivity
   between multicast sender and receiver


Monitoring
----------

To see one line per interface with the PIM and the IGMP view side by
side, the virtual interface table, the neighboring PIM routers, and the
multicast routing table:

    pimctl show summary
    pimctl show interface
    pimctl show neighbor
    pimctl show mrt

`show mrt` is what the daemon believes.  What the kernel actually
forwards is `show mfc`: one line per (S,G) with the incoming interface,
the outgoing interface list, and the kernel's packet, byte and
wrong-interface counters for that flow.

    pimctl show mfc

The IGMP side has commands of its own, `pimctl show igmp groups` and
`pimctl show igmp interface`, or `pimctl show igmp` for both at once.  A
few spellings people type anyway work as hidden aliases: `show if` and
`show interfaces` for `show interface`, `show routes` for `show mrt`, and
`show groups` for `show igmp groups`.

The default command is `pimctl show pim`.  To watch it continually
(notice the `-c` flag to watch(1) to tell it to interpret the ANSI
escape sequences):

    watch -cd pimctl

See the `pimctl help` usage text for more commands (available only when
a running PIM daemon is available), or the pimctl(8) man page.

Also worth mentioning, `pimd` logs important events to the system log,
in particular at startup when it parses the `pimd.conf` configuration
file.


Large Setups
------------

pimd is limited to the number of `MAXVIFS` interfaces listed in the
kernel headers.  In Linux see `/usr/include/linux/mroute.h`, on FreeBSD
see `/usr/include/netinet/ip_mroute.h`.

To overcome this limitation, adjust the kernel `#define` to, e.g., 1280,
and configure pimd `--with-max-vifs=1280`.  Please note, this has only
been tested with Linux and will likely not work with other kernels!

With this many interfaces the kernel may run out of memory to let pimd
to enable IGMP on all interfaces.  In Linux, use sysctl to tweak the
following settings:

    sysctl -w net.core.optmem_max=327680
    sysctl -w net.ipv4.igmp_max_memberships=5120


Build & Install
---------------

The configure script and Makefile supports de facto standard settings
and environment variables such as `--prefix=PATH` and `DESTDIR=` for the
install process.  E.g., to install pimd to `/usr` instead of the default
`/usr/local`, but redirect install to a package directory in `/tmp`:

    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var
	make
    make DESTDIR=/tmp/pimd-3.0 install-strip

On FreeBSD the build is the same, base system `make` included: the
generated Makefiles carry no GNU make syntax, and the one directive the
two spell differently, the dependency file `include`, is what `configure`
probes for before it writes them.  `gmake` builds the tree as well, if
that is what you have.

The RPF lookups PIM depends on go over the routing socket there.  On
FreeBSD 13.2 and later `--enable-netlink` uses `netlink(4)` for them
instead, the interface Linux has always used, which then needs the
`netlink` kernel module at run time.  Both read the same routing table
and the same per-route metric, so this is a build-time choice and
nothing more; `pimctl show status` reports which one a daemon has.


Building from GIT
-----------------

If you want to contribute, or simply just try out the latest but
unreleased features, then you need to know a few things about the
[GNU build system][buildsystem]:

- `configure.ac` and a per-directory `Makefile.am` are key files
- `configure` and `Makefile.in` are generated from `autogen.sh`
- `Makefile` is generated by `configure` script

To build from GIT you first need to clone the repository and run the
`autogen.sh` script.  This requires `automake` and `autoconf` to be
installed on your system.

    git clone https://github.com/ocochard/pimd.git
    cd pimd/
    ./autogen.sh
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var && make

On FreeBSD, `pkg install autoconf automake pkgconf` first; the rest is
the same, base system `make` and all.

GIT sources are a moving target and are not recommended for production
systems, unless you know what you are doing!


Testing
-------

Configure with `--enable-test` to build the test tools, then:

    make check

The automake suite in `test/` is empty: `make check` builds the test
tools and runs no test.  What it used to run lives in `test/lab.sh`,
which asserts more of the same and runs on both systems, but needs real
root and named namespaces — neither of which automake's unprivileged
`unshare -mrun` can give it.

`test/lab.sh` is that lab.  On FreeBSD it builds its topologies out of
vnet jails, epairs and `if_bridge`, and is the only regression test that
exercises the BSD routing socket and kernel glue rather than merely
compiling it; on Linux it runs the same scenarios over named network
namespaces, as root.  GENERIC needs nothing added to run
it — VIMAGE is in it and both modules ship with it — they just have to be
loaded first, since a jail may not `kldload`:

    kldload -n ip_mroute if_bridge
    sh test/lab.sh run all

It is out of `make check`: automake drives `TESTS` under an
unprivileged `unshare -mrun`, and the lab wants root, half an hour, and
on FreeBSD a host-global sysctl
(`net.inet.ip.mcast.loop`, restored when it finishes).  The [FreeBSD][]
workflow runs it on every push instead.

A third suite, `test/freebsd-interop.sh`, runs pimd against an Arista
vEOS under bhyve.  The other two have pimd at both ends of every
exchange, so a message pimd encodes wrongly is a message pimd decodes
wrongly in the same way and the run stays green; this one is what
catches that.  It needs a vEOS-lab image — `vEOS64-lab-<version>.qcow2`,
a free-account download from arista.com that cannot ship here — named
with `-i`, so it too is run by hand:

    sh test/freebsd-interop.sh -i ~/vEOS64-lab-4.36.1F.qcow2 run all

How much of pimd any of that reaches is measured rather than argued
about: configure `--enable-coverage`, run the lab with `COVERAGE=yes` or
the committed fuzz corpus through `make check`, and `test/coverage.sh
report` prints the table and the lines nothing reached.
**[doc/README-coverage.md][coverage]** is the recipe and, more usefully,
what the number cannot see; the [Coverage][] workflow runs both halves
weekly.

**[test/README.md][tests]** describes all three: what every scenario
covers, what only it covers, and what each suite requires.  See also the
header of each script for its topology, and the [Linux][] and
[FreeBSD][] workflows for how CI runs them.


Contributing
------------

pimd was restored and maintained for many years by [Joachim Wiberg][] at
[troglobit/pimd][upstream].  This repository is where it is maintained
now, and where the FreeBSD work and the changes listed in the
[ChangeLog][] happen.  Bugs, feature requests and patches go to [this
repository's issue tracker][issues]; do not file them against the project
this one forked from.  To contribute fixes or features, check out the
code from GitHub:

	git clone https://github.com/ocochard/pimd
	cd pimd

See the file [CONTRIBUTING.md][contrib] for further details.


Origin & References
-------------------

Part of this program has been derived from mrouted.  The mrouted program
is covered by the 3-clause BSD license in the accompanying file named
[LICENSE.mrouted](doc/LICENSE.mrouted).

The mrouted program is COPYRIGHT 2002 by The Board of Trustees of Leland
Stanford Junior University.


[License]:         https://en.wikipedia.org/wiki/BSD_licenses
[License Badge]:   https://img.shields.io/badge/License-BSD%203--Clause-blue.svg
[github]:          https://github.com/ocochard/pimd
[upstream]:        https://github.com/troglobit/pimd
[issues]:          https://github.com/ocochard/pimd/issues
[ChangeLog]:       https://github.com/ocochard/pimd/blob/master/ChangeLog.md
[releases page]:   https://github.com/troglobit/pimd/releases
[buildsystem]:     https://autotools.io/
[RFC 7761]:        https://datatracker.ietf.org/doc/html/rfc7761
[RFC 5059]:        https://datatracker.ietf.org/doc/html/rfc5059
[compliance]:      https://github.com/ocochard/pimd/blob/master/doc/rfc7761-compliance.md
[contrib]:         https://github.com/ocochard/pimd/blob/master/.github/CONTRIBUTING.md
[tests]:           https://github.com/ocochard/pimd/blob/master/test/README.md
[Joachim Wiberg]:  https://troglobit.com
[Linux]:           https://github.com/ocochard/pimd/actions/workflows/ci-linux.yml
[Linux Status]:    https://github.com/ocochard/pimd/actions/workflows/ci-linux.yml/badge.svg
[FreeBSD]:         https://github.com/ocochard/pimd/actions/workflows/ci-freebsd.yml
[FreeBSD Status]:  https://github.com/ocochard/pimd/actions/workflows/ci-freebsd.yml/badge.svg
[CodeQL]:          https://github.com/ocochard/pimd/actions/workflows/codeql.yml
[CodeQL Status]:   https://github.com/ocochard/pimd/actions/workflows/codeql.yml/badge.svg
[coverage]:        https://github.com/ocochard/pimd/blob/master/doc/README-coverage.md
[Coverage]:        https://github.com/ocochard/pimd/actions/workflows/coverage.yml
[Coverity Scan]:   https://scan.coverity.com/projects/33273
[Coverity Status]: https://scan.coverity.com/projects/33273/badge.svg
