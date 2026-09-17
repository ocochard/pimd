EXTRA_DIST         = README.md igmpv3.c lib.sh mping.c pimsend.c rp.sh single.sh two.sh
# Not in TESTS: needs root and FreeBSD vnet jails or Linux named netns, see the script header
EXTRA_DIST        += lab.sh lab-freebsd.sh lab-linux.sh
# Not in TESTS either: needs bhyve and a licensed Arista vEOS image on top
EXTRA_DIST        += freebsd-interop.sh veos-bhyve.sh
CLEANFILES         = *~ *.trs *.log

noinst_PROGRAMS    = mping igmpv3 pimsend
mping_SOURCES      = mping.c
igmpv3_SOURCES     = igmpv3.c
pimsend_SOURCES    = pimsend.c

TEST_EXTENSIONS    = .sh
TESTS_ENVIRONMENT  = unshare -mrun

# What is left of the unprivileged suite: everything else it used to run is
# a scenario of lab.sh now, which asserts the same and more, see README.md
TESTS              = rp.sh
TESTS             += single.sh
TESTS             += two.sh
