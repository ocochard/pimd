EXTRA_DIST         = igmpv3.c lib.sh mping.c pod.sh rp.sh shared.sh single.sh ssm.sh three.sh two.sh
# Not in TESTS: needs FreeBSD vnet jails and root, see the script header
EXTRA_DIST        += freebsd-lab.sh
CLEANFILES         = *~ *.trs *.log

noinst_PROGRAMS    = mping igmpv3
mping_SOURCES      = mping.c
igmpv3_SOURCES     = igmpv3.c

TEST_EXTENSIONS    = .sh
TESTS_ENVIRONMENT  = unshare -mrun

TESTS              = pod.sh
TESTS             += rp.sh
TESTS             += shared.sh
TESTS             += single.sh
TESTS             += ssm.sh
TESTS             += three.sh
TESTS             += two.sh
