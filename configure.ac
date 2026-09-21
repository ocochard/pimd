AC_PREREQ(2.61)
AC_INIT(pimd, 3.2-beta1, https://github.com/ocochard/pimd/issues, , https://github.com/ocochard/pimd)
AC_CONFIG_AUX_DIR(aux)
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES([yes])

AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([Makefile include/Makefile man/Makefile src/Makefile test/Makefile pimd.service])

# Check for standard programs, headers, and functions
AC_PROG_CC
AC_PROG_INSTALL
# src/ builds the daemon's objects into a static convenience library, which
# needs an archiver and a ranlib to exist by name
AM_PROG_AR
AC_PROG_RANLIB

# Check build host, differnt for each operating system
AC_CANONICAL_HOST

case $host_os in
    dragonfly*)
	CPPFLAGS="$CPPFLAGS -I../include/dragonfly"
	;;
    netbsd*)
        CPPFLAGS="$CPPFLAGS -D_OPENBSD_SOURCE"
        ;;
    solaris2.5)
	CPPFLAGS="$CPPFLAGS -DSYSV -DSunOS=55 -I../include/sunos-gcc"
	LIBS="-lsocket -lnsl"
	;;
    solaris2.6)
	CPPFLAGS="$CPPFLAGS -DSYSV -DSunOS=56 -I../include/sunos-gcc"
	LIBS="-lsocket -lnsl"
	;;
    solaris2.7|solaris2.8|solaris2.9|solaris2.10|solaris2.11|solaris2.12)
	CPPFLAGS="$CPPFLAGS -DSYSV -DSunOS=57"
	LIBS="-lsocket -lnsl"
	;;
    linux*)
	# -D_GNU_SOURCE Use GNU extensions, where possible (GLIBC)
	# -D_BSD_SOURCE Use functions derived from 4.3 BSD Unix rather than POSIX.1
	#               In GLIBC >= v2.20 this is replaced with -D_DEFAULT_SOURCE,
	#               but to build on older GLIBC systems we now need both ...
	CPPFLAGS="$CPPFLAGS -D_BSD_SOURCE -D_DEFAULT_SOURCE -D_GNU_SOURCE"
	;;
    *)
        ;;
esac

# Required to check for libsystemd-dev
PKG_PROG_PKG_CONFIG

AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h ifaddrs.h netinet/pim.h net/if_dl.h sys/time.h sys/ioctl.h linux/netlink.h termios.h])
# The sandbox the unprivileged half of the daemon enters: seccomp-bpf on
# Linux, and nothing on the BSDs -- Capsicum refuses every sendto() that
# carries a destination, which is every packet pimd sends.  The long version
# is in src/privsep.c, above priv_sandbox_enter().
AC_CHECK_HEADERS([linux/seccomp.h linux/filter.h linux/audit.h sys/prctl.h])
# How the unprivileged half asks to be signalled if its parent dies:
# prctl(PR_SET_PDEATHSIG) on Linux, procctl(PROC_PDEATHSIG_CTL) on FreeBSD.
AC_CHECK_HEADERS([sys/procctl.h])
AC_CHECK_HEADERS([netlink/netlink.h netlink/netlink_route.h])
AC_CHECK_HEADERS([net/if.h], [], [], [
#include <stdio.h>
#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif])

# Check if some func is not in libc
AC_CHECK_LIB([util], [pidfile])

# Check for required functions in libc
AC_CHECK_FUNCS([atexit getifaddrs if_nametoindex getentropy])

# RFC 7761 sec. 4.6.3 reads the metric an Assert carries off the unicast
# routing table.  FreeBSD keeps a per-nexthop metric in struct rt_metrics
# and returns it with every routing socket reply; where the field is
# missing, routesock.c falls back to the value from pimd.conf.
AC_CHECK_MEMBERS([struct rt_metrics.rmx_metric], [], [], [[
#include <sys/types.h>
#include <sys/socket.h>
#include <net/route.h>
]])

# Check for usually missing API's, which we can replace
AC_REPLACE_FUNCS([arc4random pidfile strlcpy strlcat strtonum tempfile utimensat])
AC_CONFIG_LIBOBJ_DIR([lib])

#   Register kernel encapsulation.  Your kernel must support registers
#   kernel encapsulation to be able to use it.
AC_ARG_ENABLE(kernel_encap,
	AS_HELP_STRING([--enable-kernel-encap], [Specialized kernels do PIM Register encapsulation
			by themselves, speeding up processing considerably.
			Not available on Linux, but maybe on *BSD, needs pimkern-PATCH_6]),,
	enable_kernel_encap=no)

#   (*,G) kernel MFC support.  Use it ONLY with (*,G) capable kernel
AC_ARG_ENABLE(kernel_mfc,
	AS_HELP_STRING([--enable-kernel-mfc], [Specialized kernels may have (*,G) MFC support.
			Not on Linux, but maybe on *BSD, needs pimkern-PATCH_7]),,
	enable_kernel_mfc=no)

#   Saves 4 bytes per unconfigured interface per routing entry.  If set,
#   configuring such interface will restart the daemon and will flush
#   the routing table.
AC_ARG_ENABLE(memory_save,
	AS_HELP_STRING([--enable-memory-save], [Save 4 bytes/unconfigured interface/routing entry.
			Must restart pimd and cause routing table to be flushed when configuring
			new interfaces.]),,
	enable_memory_save=no)

#   The unicast RPF lookups PIM depends on.  netlink.c is the only way to
#   ask on Linux, where it is not a choice at all, but FreeBSD 13.2 and
#   later answer the same RTM_GETROUTE through netlink(4), and map its
#   RTA_PRIORITY onto the same rt_metrics.rmx_metric routesock.c reads.
#   The routing socket stays the default there: it needs no kernel module
#   and it is what test/lab.sh exercises.
AC_ARG_ENABLE(netlink,
	AS_HELP_STRING([--enable-netlink], [Use netlink(4) for RPF lookups instead of the
			routing socket.  Always used on Linux; elsewhere needs
			FreeBSD 13.2 or later and the netlink kernel module.]),,
	enable_netlink=no)

AC_ARG_ENABLE(test,
        AS_HELP_STRING([--enable-test], [enable tests, requries unshare, tshark, etc.]),
        enable_test="$enableval", enable_test="no")

AC_ARG_ENABLE(exit_on_error,
        AS_HELP_STRING([--disable-exit-on-error], [Do not exit on error messages (LOG_ERR)]),,
	enable_exit_on_error=yes)

AC_ARG_ENABLE(fuzz,
        AS_HELP_STRING([--enable-fuzz], [Build the fuzz harnesses in test/fuzz/, needs clang
		for the libFuzzer half; the corpus replay builds with any compiler]),,
	enable_fuzz=no)

AC_ARG_WITH(max_vifs,
	AS_HELP_STRING([--with-max-vifs=NUM], [Kernel maximum number of allowed VIFs, default: 32.
		This must match the kernel built-in MAXVIFS value!
		Usually, multiple routing tables is what you want.]),
	[max_vifs=$withval], [max_vifs=yes])

AC_ARG_WITH([systemd],
     [AS_HELP_STRING([--with-systemd=DIR], [Directory for systemd service files])],,
     [with_systemd=auto])

# The user the unprivileged half of the daemon runs as.  nobody, because it
# is there on every system this builds for and a daemon that separates by
# default must not need an account somebody remembered to create first.  It
# has to exist on the running system rather than on this one, so this is a
# name and not a probe: a missing user is a start-up error naming
# --no-privsep, never a silent fall back to the root pimd this exists to
# stop being.
#
# A user of pimd's own, shared with no other daemon, is stronger -- two
# under one uid can signal and trace each other -- so a packager who
# creates one should build with it here.
AC_ARG_WITH([privsep-user],
	AS_HELP_STRING([--with-privsep-user=USER], [User the unprivileged half runs as,
		default: nobody]),
	[privsep_user=$withval], [privsep_user=nobody])
AC_DEFINE_UNQUOTED([PRIVSEP_USER], ["$privsep_user"],
	[User the unprivileged half of the daemon runs as.])

# The directory the unprivileged half is confined to.  It needs nothing in
# it and must have nothing in it: by the time the daemon gets there the
# child reads its configuration from a descriptor the parent opened, and
# the PID file, the pimctl socket and syslog(3) all belong to the parent,
# so there is no path left for it to want.  /var/empty is the BSD
# convention and is created if it is not there.
AC_ARG_WITH([privsep-chroot],
	AS_HELP_STRING([--with-privsep-chroot=DIR], [Directory the unprivileged half is confined
		to, default: /var/empty.  --without-privsep-chroot does not chroot at all]),
	[privsep_chroot=$withval], [privsep_chroot=/var/empty])
AS_IF([test "x$privsep_chroot" = "xno"], [privsep_chroot=])
AC_DEFINE_UNQUOTED([PRIVSEP_CHROOT], ["$privsep_chroot"],
	[Directory the unprivileged half is confined to, empty to not chroot.])

# The harnesses call the parsers in-process, and they live in test/, so
# --enable-fuzz has to reach two other knobs.  --disable-exit-on-error is
# not a preference here but a requirement: logit(LOG_ERR) calls exit(-1),
# which every fuzzer reads as a crash, so without it the first
# configuration pimd refuses -- a syntax error, say -- ends the run.
AS_IF([test "x$enable_fuzz" = "xyes"], [
	enable_exit_on_error=no
	enable_test=yes])

# libFuzzer is clang's, ships as part of it, and supplies the main() a
# harness has none of -- so the probe is a link of a translation unit that
# defines LLVMFuzzerTestOneInput() and nothing else.  Without it only the
# corpus replay is built, which needs no fuzzer at all.
have_libfuzzer=no
fuzz_coverage=no
AS_IF([test "x$enable_fuzz" = "xyes"], [
	AC_MSG_CHECKING([whether $CC can link -fsanitize=fuzzer])
	pimd_save_CFLAGS="$CFLAGS"
	pimd_save_LDFLAGS="$LDFLAGS"
	CFLAGS="$CFLAGS -fsanitize=fuzzer"
	LDFLAGS="$LDFLAGS -fsanitize=fuzzer"
	AC_LINK_IFELSE([AC_LANG_SOURCE([[
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	(void)data;
	(void)size;
	return 0;
}
	]])], [have_libfuzzer=yes], [have_libfuzzer=no])
	CFLAGS="$pimd_save_CFLAGS"
	LDFLAGS="$pimd_save_LDFLAGS"
	AC_MSG_RESULT([$have_libfuzzer])])

# Create config.h from selected features and fallback defaults
AS_IF([test "x$enable_kernel_encap" = "xyes"], [
        AC_DEFINE(PIM_REG_KERNEL_ENCAP, 1, [Use kernel accelerated PIM register encap/decapsulation.])])

AS_IF([test "x$enable_kernel_mfc" = "xyes"], [
        AC_DEFINE(KERNEL_MFC_WC_G, 1, [Use kernel (*,G) MFC support.])])

AS_IF([test "x$enable_memory_save" = "xyes"], [
        AC_DEFINE(SAVE_MEMORY, 1, [Save 4 bytes/unconfigured interface/routing entry.])])

AS_IF([test "x$enable_exit_on_error" = "xno"], [
	AC_DEFINE(CONTINUE_ON_ERROR, 1, [Do not exit on error messages (LOG_ERR).])])

AS_IF([test "x$with_max_vifs" != "xno" -a "x$max_vifs" != "xyes"], [
	AC_DEFINE_UNQUOTED(CUSTOM_MAX_VIFS, $max_vifs, [Custom MAX VIFs in kernel.])], [
	max_vifs=32])

AS_IF([test "x$with_systemd" = "xyes" -o "x$with_systemd" = "xauto"], [
     def_systemd=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
     AS_IF([test "x$def_systemd" = "x"],
         [AS_IF([test "x$with_systemd" = "xyes"],
	     [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
	     with_systemd=no], [with_systemd="$def_systemd"])]
)
AS_IF([test "x$with_systemd" != "xno"],
     [AC_SUBST([systemddir], [$with_systemd])])

# Linux has no routing socket to fall back to, so netlink is not optional
# there.  Everywhere else it is, and the headers have to be in place.
AS_IF([test "x$ac_cv_header_linux_netlink_h" = "xyes"], [enable_netlink=yes])
AS_IF([test "x$enable_netlink" = "xyes" -a "x$ac_cv_header_linux_netlink_h" != "xyes" \
	    -a "x$ac_cv_header_netlink_netlink_route_h" != "xyes"], [
	AC_MSG_ERROR([--enable-netlink given, but neither <linux/netlink.h> nor <netlink/netlink_route.h> was found])])

AS_IF([test "x$enable_netlink" = "xyes"], [rpf_backend="netlink"], [rpf_backend="routing socket"])

AM_CONDITIONAL(BSD,         [test "x$ac_cv_header_net_if_dl_h"     = "xyes"])
AM_CONDITIONAL(LINUX,       [test "x$ac_cv_header_linux_netlink_h" = "xyes"])
AM_CONDITIONAL(NETLINK,     [test "x$enable_netlink"               = "xyes"])
AM_CONDITIONAL(SYSTEMD,     [test "x$with_systemd"                != "xno"])
AM_CONDITIONAL(ENABLE_TEST, [test "x$enable_test"                 != "xno"])
AM_CONDITIONAL(ENABLE_FUZZ, [test "x$enable_fuzz"                  = "xyes"])
AM_CONDITIONAL(HAVE_LIBFUZZER, [test "x$have_libfuzzer"            = "xyes"])

# Warning and hardening flags
#
# Every flag is probed rather than assumed.  This tree builds with gcc and
# with clang, on Linux, FreeBSD, NetBSD and DragonFly, and the oldest of
# those compilers has none of the hardening options; a flag the compiler
# will not take is dropped rather than failing the configure.  The probe
# adds -Werror because clang merely warns about an option it does not know
# and would otherwise "accept" every one of them.
AC_DEFUN([PIMD_TRY_CFLAGS], [
  AC_MSG_CHECKING([whether $CC accepts $1])
  pimd_save_CFLAGS="$CFLAGS"
  CFLAGS="$pimd_probe_CFLAGS -Werror $1"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
    [AC_MSG_RESULT([yes])
     PIMD_CFLAGS="$PIMD_CFLAGS $1"],
    [AC_MSG_RESULT([no])])
  CFLAGS="$pimd_save_CFLAGS"
])

AC_DEFUN([PIMD_TRY_LDFLAGS], [
  AC_MSG_CHECKING([whether the linker accepts $1])
  pimd_save_LDFLAGS="$LDFLAGS"
  LDFLAGS="$LDFLAGS $1"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
    [AC_MSG_RESULT([yes])
     PIMD_LDFLAGS="$PIMD_LDFLAGS $1"],
    [AC_MSG_RESULT([no])])
  LDFLAGS="$pimd_save_LDFLAGS"
])

PIMD_CFLAGS=""
PIMD_LDFLAGS=""

# The probe turns warnings into errors, so a -W option of the user's own
# CFLAGS that fires on the test program would fail every probe below and
# drop the whole set without a word -- and the linker probes, which have
# no -Werror, would keep their half, leaving -pie without -fPIE.  Probe
# against the user's CFLAGS with their warning options taken out.
pimd_probe_CFLAGS=`echo " $CFLAGS " | sed -e 's/ -W[[^ ]]*/ /g'`

# The set that is silent on this tree as it stands, so -Werror stays
# usable.  -Wformat=2 is the one that matters most for a daemon parsing
# the network: it subsumes -Wformat-security and -Wformat-nonliteral, the
# same class rules/security.cocci checks with fmt_printf and friends.
# -Wno-unused stays, this being old code, but does not cover
# -Wunused-parameter in clang, which is why that is not listed here.
for flag in -W -Wall -Wextra -Wno-unused					\
	    -Wformat=2 -Wpointer-arith -Wcast-qual -Wstrict-prototypes	\
	    -Wold-style-definition -Wvla -Walloca -Wundef		\
	    -Wredundant-decls -Wimplicit-fallthrough -Wshadow		\
	    -Wmissing-prototypes -Wmissing-variable-declarations; do
	PIMD_TRY_CFLAGS([$flag])
done

AC_ARG_ENABLE([hardening],
	AS_HELP_STRING([--disable-hardening], [Do not add compiler and linker hardening flags]),,
	[enable_hardening=yes])

# -fno-strict-aliasing is not decoration here: pim.c and igmp.c cast the
# char * receive buffers to struct ip *, pim_register_t * and
# struct igmpv3_report * on nearly every path, which is undefined at the
# -O2 the autotools default CFLAGS carry.  -ftrivial-auto-var-init=zero is
# the one that matters most at runtime: the failure mode of a protocol
# parser is reading a field a short packet never carried, and it zeroes
# what would otherwise be stack residue.
AS_IF([test "x$enable_hardening" != "xno"], [
	for flag in -fstack-protector-strong -fstack-clash-protection	\
		    -fcf-protection=full -ftrivial-auto-var-init=zero	\
		    -fno-strict-aliasing -fno-delete-null-pointer-checks	\
		    -fPIE; do
		PIMD_TRY_CFLAGS([$flag])
	done

	# _FORTIFY_SOURCE needs optimisation, and redefining one the
	# distribution already set is an error, so undefine first and let
	# the probe decide.  Falls back to level 2 where 3 is not there.
	PIMD_TRY_CFLAGS([-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3])
	AS_CASE(["$PIMD_CFLAGS"], [*_FORTIFY_SOURCE=3*], [],
		[PIMD_TRY_CFLAGS([-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2])])

	# -pie needs the compiler half: linking PIE objects that were built
	# without -fPIE gives "relocation R_X86_64_32 cannot be used against
	# local symbol", so ask for it only if -fPIE was taken.
	AS_CASE([" $PIMD_CFLAGS "], [*" -fPIE "*], [PIMD_TRY_LDFLAGS([-pie])])

	for flag in -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack; do
		PIMD_TRY_LDFLAGS([$flag])
	done
])

# The daemon's own objects have to carry the coverage instrumentation, or a
# fuzzer mutates with no idea what it reached: -fsanitize=fuzzer on the
# harness alone instruments the harness alone, and the run that follows looks
# healthy -- tens of thousands of executions a second -- while exploring
# seven edges of a parser with hundreds.  Measured: 7 edges without this,
# 730 with it.  -fsanitize=fuzzer-no-link is that instrumentation without
# libFuzzer's main(), which is what the harness links for itself.
AS_IF([test "x$enable_fuzz" = "xyes"], [
	PIMD_TRY_CFLAGS([-fsanitize=fuzzer-no-link])
	AS_CASE([" $PIMD_CFLAGS "], [*" -fsanitize=fuzzer-no-link "*], [fuzz_coverage=yes],
		[fuzz_coverage=no
		 AC_MSG_WARN([$CC does not take -fsanitize=fuzzer-no-link, so the fuzz
		 harnesses will run without coverage feedback, which is little better
		 than sending random bytes.  Build them with clang.])])])

AC_ARG_ENABLE([werror],
	AS_HELP_STRING([--enable-werror], [Turn warnings into errors, for CI]),,
	[enable_werror=no])
AS_IF([test "x$enable_werror" = "xyes"], [PIMD_CFLAGS="$PIMD_CFLAGS -Werror"])

AC_SUBST(PIMD_CFLAGS)
AC_SUBST(PIMD_LDFLAGS)

# Expand $sbindir early, into $SBINDIR, for systemd unit file
# NOTE: This does *not* take prefix/exec_prefix override at "make
#       install" into account, unfortunately.
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'
DOCDIR=`eval echo $docdir`
DOCDIR=`eval echo $DOCDIR`
AC_SUBST(DOCDIR)
SYSCONFDIR=`eval echo $sysconfdir`
SYSCONFDIR=`eval echo $SYSCONFDIR`
AC_SUBST(SYSCONFDIR)
SBINDIR=`eval echo $sbindir`
SBINDIR=`eval echo $SBINDIR`
AC_SUBST(SBINDIR)

# Workaround for as-of-yet unreleased runstatedir support, planned for
# autoconf 2.70, which some major distros have backported.
AS_IF([test -z "$runstatedir"], runstatedir="$localstatedir/run")
AC_SUBST(runstatedir)

# Generate all files
AC_OUTPUT

cat <<EOF

------------------ Summary ------------------
 $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix................: $prefix
  Sysconfdir............: `eval echo $sysconfdir`
  Runstatedir...........: `eval echo $runstatedir`
  C Compiler............: $CC $CFLAGS $CPPFLAGS $LDFLAGS $LIBS
  Probed flags..........: $PIMD_CFLAGS
  Probed link flags.....: $PIMD_LDFLAGS

Optional features:
  RPF backend...........: $rpf_backend
  Kernel register encap.: $enable_kernel_encap
  Kernel (*,G) support..: $enable_kernel_mfc
  Kernel MAX VIFs.......: $max_vifs
  Memory save...........: $enable_memory_save
  Hardening.............: $enable_hardening
  Warnings are errors...: $enable_werror
  Exit on error.........: $enable_exit_on_error
  systemd...............: $with_systemd
  Privsep user..........: $privsep_user
  Privsep chroot........: ${privsep_chroot:-none}
  Unit tests............: $enable_test
  Fuzz harnesses........: $enable_fuzz (libFuzzer: $have_libfuzzer, coverage: $fuzz_coverage)

------------- Compiler version --------------
$($CC --version || true)
---------------------------------------------

Check the above options and compile with:
 ${MAKE-make}

EOF
