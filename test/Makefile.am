EXTRA_DIST         = lib.sh mping.c pod.sh rp.sh shared.sh single.sh three.sh two.sh
# Not in TESTS: needs FreeBSD vnet jails and root, see the script header
EXTRA_DIST        += freebsd-lab.sh
CLEANFILES         = *~ *.trs *.log

noinst_PROGRAMS    = mping
mping_SOURCES      = mping.c

TEST_EXTENSIONS    = .sh
TESTS_ENVIRONMENT  = unshare -mrun

TESTS              = pod.sh
TESTS             += rp.sh
TESTS             += shared.sh
TESTS             += single.sh
TESTS             += three.sh
TESTS             += two.sh
