# For replacement functions in lib/
AUTOMAKE_OPTIONS = subdir-objects

AM_CPPFLAGS      = -I$(top_srcdir)/include
AM_CPPFLAGS     += -DSYSCONFDIR=\"@sysconfdir@\" -DRUNSTATEDIR=\"@runstatedir@\"

sbin_PROGRAMS    = pimd pimctl
pimd_SOURCES     = config.c		debug.c		debug.h			    \
		   defs.h		dvmrp_proto.c	dvmrp.h			    \
		   igmp_proto.c		igmp.c		igmpv2.h	igmpv3.h    \
		   inet.c		ipc.c		kern.c			    \
		   main.c		mrt.c		mrt.h		    	    \
		   pathnames.h		pim_proto.c	pim.c		pimd.h	    \
		   queue.h		route.c		rp.c			    \
		   timer.c		trace.c		trace.h	    		    \
		   vif.c		vif.h
pimd_CFLAGS      = -W -Wall -Wextra -Wno-unused
pimd_LDADD       = $(LIBS) $(LIBOBJS)

if LINUX
AM_CPPFLAGS     += -DRAW_OUTPUT_IS_RAW -DIOCTL_OK_ON_RAW_SOCKET
endif

# The RPF lookups, one file or the other: netlink.c always on Linux, and
# on BSD only when configured with --enable-netlink.
if NETLINK
pimd_SOURCES    += netlink.c
else
if BSD
pimd_SOURCES    += routesock.c
endif
endif

pimctl_SOURCES   = pimctl.c		queue.h
pimctl_LDADD     = $(LIBS) $(LIBOBJS)
