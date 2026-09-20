# For replacement functions in lib/
AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS        = @PIMD_CFLAGS@
AM_LDFLAGS       = @PIMD_LDFLAGS@
AM_CPPFLAGS      = -I$(top_srcdir)/include
AM_CPPFLAGS     += -DSYSCONFDIR=\"@sysconfdir@\" -DRUNSTATEDIR=\"@runstatedir@\"

sbin_PROGRAMS    = pimd pimctl

# Everything but main.c, in a convenience library rather than in
# pimd_SOURCES, so that something else can link the daemon's own objects
# without a second copy of this list: the fuzz harnesses of test/fuzz/ call
# the parsers in-process, and a harness supplies its own main().  Nothing
# about the pimd binary changes -- the library is static, built from the
# same sources with the same flags, and is not installed.
noinst_LIBRARIES = libpimd.a
libpimd_a_SOURCES = config.c		debug.c		debug.h			    \
		   defs.h		dvmrp_proto.c	dvmrp.h			    \
		   igmp_proto.c		igmp.c		igmpv2.h	igmpv3.h    \
		   inet.c		ipc.c		kern.c			    \
		   mrt.c		mrt.h		    			    \
		   pathnames.h		pim_proto.c	pim.c		pimd.h	    \
		   queue.h		route.c		rp.c			    \
		   timer.c		trace.c		trace.h	    		    \
		   vif.c		vif.h

# The lib/ replacements go into the archive rather than beside it, so that
# one -l is the whole daemon: a program in another directory linking
# libpimd.a would otherwise need LIBOBJS as well, and automake sets the
# path they live at only in the directory that asks for them.
libpimd_a_LIBADD = $(LIBOBJS)

pimd_SOURCES     = main.c
pimd_LDADD       = libpimd.a $(LIBS)

if LINUX
AM_CPPFLAGS     += -DRAW_OUTPUT_IS_RAW -DIOCTL_OK_ON_RAW_SOCKET
endif

# The RPF lookups, one file or the other: netlink.c always on Linux, and
# on BSD only when configured with --enable-netlink.
if NETLINK
libpimd_a_SOURCES += netlink.c
else
if BSD
libpimd_a_SOURCES += routesock.c
endif
endif

pimctl_SOURCES   = pimctl.c		queue.h
pimctl_LDADD     = $(LIBS) $(LIBOBJS)
