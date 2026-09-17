EXTRA_DIST         = README.md anycast.sh igmpv3.c lib.sh mping.c pimsend.c pod.sh rp.sh shared.sh single.sh ssm.sh three.sh two.sh
# Not in TESTS: needs FreeBSD vnet jails and root, see the script header
EXTRA_DIST        += freebsd-lab.sh
# Not in TESTS either: needs bhyve and a licensed Arista vEOS image on top
EXTRA_DIST        += freebsd-interop.sh veos-bhyve.sh
CLEANFILES         = *~ *.trs *.log

noinst_PROGRAMS    = mping igmpv3 pimsend
mping_SOURCES      = mping.c
igmpv3_SOURCES     = igmpv3.c
pimsend_SOURCES    = pimsend.c

TEST_EXTENSIONS    = .sh
TESTS_ENVIRONMENT  = unshare -mrun

TESTS              = anycast.sh
TESTS             += pod.sh
TESTS             += rp.sh
TESTS             += shared.sh
TESTS             += single.sh
TESTS             += ssm.sh
TESTS             += three.sh
TESTS             += two.sh
