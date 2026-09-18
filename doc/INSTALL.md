Installation instruction for pimd
=================================

It is recommended to use a pimd from your distribution, be it from ports
in one of the major BSD's, or your GNU/Linux distribution of choice.

However, if you want to try the latest bleeding edge pimd, clone the GIT
sources from <https://github.com/ocochard/pimd>.  The 2.x release
tarballs predate this fork and are still on the releases page of the
project it forked from, <https://github.com/troglobit/pimd/releases>;
report anything about the sources here in this repository's tracker,
<https://github.com/ocochard/pimd/issues>.

After unpacking the tarball, cd to the new directory, e.g. `pimd-3.0/`
followed by:

    ./configure && make
    sudo make install

On FreeBSD the base system `make` runs every command here, `make check`,
`make install` and `make dist` included: the generated Makefiles carry no
GNU make syntax, and `configure` probes for the one directive the two
spell differently -- the dependency file `include` -- falling back to the
BSD spelling, or to no dependency tracking, for a make that has neither.
The same probe runs on NetBSD, OpenBSD and DragonFly; `gmake` from
packages is the answer wherever it turns out not to be enough.

By default pimd is installed to the `/usr/local` prefix, except for
`pimd.conf` which is installed to `/etc`.  If you want to install to
another directory, e.g. `/opt`, use:

    ./configure --prefix=/opt && make
    sudo make install

This will change both the `--prefix` and the `--sysconfdir` paths.  To
install `pimd.conf` to another path, add `--sysconfdir` *after* the
`--prefix` path.

For distribution packagers and ports maintainers, the pimd `Makefile`
supports the use of `DESTDIR=` to install to a staging directory.  What
you want is probably something like:

    ./configure --prefix=/usr --sysconfdir=/etc && make
    make DESTDIR=/tmp/staging install-strip

The default `/etc/pimd.conf` should be good enough for most use cases.
But if you edit it, see the man page or the comments in the file for
some help.

NetBSD and FreeBSD users may have to install the kernel modules to get
multicast routing support, including PIM support.  See your respective
documentation, or consult the web for help!


OpenBSD
-------

PIM support was unfortunately removed from the multicast stack as of
[OpenBSD 6.1](https://marc.info/?l=openbsd-cvs&m=148240469327159)

For instructions on installing pimd on OpenBSD 6.0, and earlier, you can
use Joachim Wiberg's
[HOWTO](https://troglobit.com/howto-run-pimd-on-openbsd.html),
taking into account the following:

1. The MROUTING option is enabled by default in the kernel, but the PIM
   option is not.  In `/src/sys/conf/GENERIC`, uncomment the following
   line and rebuild the kernel:

   ```
   options   PIM              # Enable for pimd
   ```

2. The multicast configuration option in `/etc/rc.conf.local` now only
   consists of one line instead of the two mentioned in the HOWTO
   document:

   ```
   # Multicast routing configuration
   # Please look at netstart(8) for a detailed description if you change these
   multicast=YES           # Reject IPv4 multicast packets by default
   ```


Cross Compiling
---------------

As of pimd 3.0 the build system is GNU autotools, so cross-compiling is
the usual `--host=` dance: name the target triplet and `configure` looks
for a toolchain prefixed with it.  E.g.

    ./configure --host=arm-linux-gnueabi --prefix=/usr
    make

The tools have to be in `PATH`.  If they are not named after the triplet
`--host` was given, name the compiler yourself:

    ./configure --host=arm-linux-gnueabi CC=arm-linux-gnueabi-gcc

**Note:** the `CROSS=` variable and the `--embedded-libc` flag of pimd
  2.x are gone; both belonged to the hand-written build system that
  autotools replaced.


Old INSTALL
-----------

Old install instructions, before PIM kernel support was readily
available in all major operating systems.  The command line below is
pimd 2.x and earlier: the config file is `-f` today, not `-c`, and most
of the debug levels listed have been renamed or removed.  `pimd -h`
lists the ones that exist.

1. Apply the PIM kernel patches, recompile, reboot

2. Copy pimd.conf to /etc and edit as appropriate.  Disable the
   interfaces you don't need. Note that you need at least 2 physical
   interfaces enabled.

3. Edit Makefile by uncommenting the line(s) corresponding to your platform.

4. Recompile pimd

5. Run pimd as a root. It is highly recommended to run it in debug mode.
   Because there are many debug messages, you can specify only a subset of
   the messages to be printed out:

        usage: pimd [-c configfile] [-d [debug_level][,debug_level]]

   Valid debug levels: `dvmrp_prunes`, `dvmrp_mrt`, `dvmrp_neighbors`,
   `dvmrp_timers`, `igmp_proto`, `igmp_timers`, `igmp_members`, `trace`,
   `timeout`, `pkt`, `interfaces`, `kernel`, `cache`,
   `pim_hello`, `pim_register`, `pim_join_prune`, `pim_bootstrap`,
   `pim_asserts`, `pim_cand_rp`, `pim_routes`, `pim_timers`, `pim_rpf`

   If you want to see all messages, use `pimd -dall` only.

6. Note that it takes of the order of 30 seconds to 1 minute until the
   Bootstrap router is elected and the RP-set distributed to the PIM
   routers, and without the RP-set in the routers the multicast packets
   cannot be forwarded.

7. There are plenty of bugs, some of them known (check `doc/TODO.org`),
   some of them unknown, so your bug reports are more than welcome.


