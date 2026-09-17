EXTRA_DIST         = README.md igmpv3.c mping.c pimsend.c
# Not in TESTS: needs root and FreeBSD vnet jails or Linux named netns, see the script header
EXTRA_DIST        += lab.sh lab-freebsd.sh lab-linux.sh
# Not in TESTS either: needs bhyve and a licensed Arista vEOS image on top
EXTRA_DIST        += freebsd-interop.sh veos-bhyve.sh
CLEANFILES         = *~ *.trs *.log

noinst_PROGRAMS    = mping igmpv3 pimsend
mping_SOURCES      = mping.c
igmpv3_SOURCES     = igmpv3.c
pimsend_SOURCES    = pimsend.c

# No TESTS: every script that was here is a scenario of lab.sh now, which
# asserts the same and more and runs on FreeBSD as well, but wants real
# root and named namespaces -- neither of which automake's `unshare -mrun`
# can give it.  CI runs it as a job of its own on both systems.
