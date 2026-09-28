Line coverage
=============

Which lines of pimd the tests reach, as a number rather than as a thing
somebody remembers reading.  Everything here is `--enable-coverage`, the
gcov instrumentation both gcc and clang spell `--coverage`: the compiler
leaves a `.gcno` beside each object, and every program writes a `.gcda`
beside it as it exits.  `test/coverage.sh` turns what a run left behind
into a table and a list of the lines nothing reached.

This is a measurement, not a test.  Nothing fails because a number moved;
what the number is for is deciding whether the next test is worth writing,
and which one.


Running it
----------

Two runs answer two different questions, and they are two builds because
`--enable-fuzz` implies `--disable-exit-on-error` -- a daemon that carries
on past `logit(LOG_ERR)` is not the daemon the lab asserts against, so the
labs do not run in a fuzz build.

The lab suite, which is where nearly all of it comes from:

    ./configure --enable-coverage --enable-test CFLAGS="-O0 -g"
    make
    test/coverage.sh reset
    sudo env COVERAGE=yes sh test/lab.sh -j 4 run all
    test/coverage.sh -n lab report

The committed fuzz corpus, which needs neither root nor a network:

    make distclean
    ./configure --enable-coverage --enable-fuzz CFLAGS="-O0 -g"
    make
    test/coverage.sh reset
    make check
    test/coverage.sh -n fuzz report

`-O0` is not decoration.  At `-O2` a line count is the optimiser's idea of
which line the code came from, and a function that was inlined into its
only caller reports as never executed.  `--enable-coverage` turns the
hardening flags off by itself for a related reason: `_FORTIFY_SOURCE` wants
an optimiser and says so, from every header, on every file.

`test/coverage.sh reset` deletes the counters and keeps the `.gcno`, so a
run is measured on its own.  Without it a report is every run since the
build, which is a fine thing to want and a terrible thing to get by
accident.


What it says today
------------------

Measured on FreeBSD with clang, `--enable-coverage CFLAGS="-O0 -g"`, on the
tree as of 2026-09-28:

  - the lab suite, 31 scenarios green at `-j 12` in 8m34s on 16 cores,
    reaches **72.3%** of the 12993 instrumented lines of `src/` and `lib/`;
  - the fuzz corpus replay reaches **33.1%** of the 10060 its own build
    instruments -- fewer files, `main.c`, `ipc.c` and `pimctl.c` not being
    linked into the harnesses at all.  That half was last measured over 23
    lab scenarios and has not been re-run since.

It was 72.2% of 12992 before the three administrative-boundary commits, and
that pair is the clearest illustration in this file of what the number is not.
Those commits fixed a boundary that applied to every interface of a router
rather than to its own, made it survive the entry being reinstalled, and added
the inbound direction; they came with three lab steps and a second receiver
LAN, and one of those steps fails two assertions on the old code.  All of that
moved the table by ten lines and a tenth of a point -- the boundary conditions
are a handful of lines, and what the steps buy is telling two readings of them
apart, which no line count can see.  The denominator moved by one line in the
same commits, `src/kern.c` gaining three and `src/route.c` losing two with the
macro that went.

Before them it was 71.5% of 12992, and the `altnet` scenario is the
whole of the difference: it writes the two `phyint` keywords about addresses,
`altnet` and `scoped`, that no other scenario writes, and it took `config.c`
from 630 unreached lines to 555 -- 75 of the 84 the suite gained, with 3 more
in `vif.c`, where `find_vif_direct()` walks a VIF's altnets, and 3 in
`route.c`, where `scoped_addr()` answers the boundary test.  All but four lines
of `parse_phyint()`'s altnet and scoped block now execute; the four are the two
`WARN` arms that `return FALSE` and abort the whole configuration read, which
no scenario can carry beside a working one, and two allocation failures.

Before that it was 71.1% of the same 12992, and that pair *is* subtractable
too, the tree not having moved between them: four steps added to
`crafted` -- a Join/Prune cut short of its own fields, a (\*,\*,RP) one, an
(S,G) Prune with nobody to wait for, and a shared tree Prune for an SSM group
-- reached 61 lines nothing had reached before, 49 of them in `pim_proto.c`
and 3 in `pim.c`, the rest falling out in `route.c` and `rp.c` behind the
prune paths.  Two files moved the other way by a handful of lines,
`autorp.c` and `routesock.c`: that is run-to-run variance in timing-dependent
paths and not a regression, and it is the reason to read a file's number as a
range rather than a value.

The measurement before those two, over the 23 scenarios of the day, was 67.3%
of 11442 lines.  Both halves of that moved, so the two are not one number
minus the other: seven scenarios were added, and so was the code some of
them are about -- `src/autorp.c` alone is 698 lines that did not exist.
What the comparison says is that the suite grew faster than the tree, not
that 3.8 points of previously unreached code are now reached.

The instrumentation costs the labs little: the same scenarios take about
seven minutes at `-j 14` without it.  What a coverage build does cost is a
scenario's margin, every assertion in the lab being a poll against a
deadline, so read a number from a green run and re-run a scenario that
tripped on its own before believing it.

One scenario skips a step rather than failing it on this host, and that is
by design: `shared-lan` step 13 wants the protocol that installed a route,
which only the netlink backend can name, so a routing socket build says so
and moves on.  Nothing in the table is missing because of it.

The top of that table, and what it settles:

  - `src/pim_proto.c`: 642 lines, 77.7%, and still the largest block in the
    table.  This is the one worth reading the ranges of, being the file
    every attacker-supplied PIM message is parsed in.  About a hundred of
    those lines cannot be reached at all: they are the (\*,\*,RP) handling
    RFC 7761 removed, working on an entry `create_mrtentry()` never makes,
    and `doc/rfc7761-compliance.md` and `doc/TODO.org` say so with the
    evidence.
  - `src/config.c`: 555 lines, 67.9%, the second largest, and mostly single
    lines rather than blocks -- allocation failures, `logit(LOG_ERR)` arms,
    and keywords no scenario writes into a `pimd.conf`.  `altnet` and
    `scoped` were the largest of those and are written now; what is left is
    the same shape, one keyword at a time.
  - `src/debug.c`: 343 lines, 22.2%, and the third largest -- which is the
    clearest illustration of why this table is not a ranking.  Those lines
    are the DVMRP and mtrace arms of `packet_kind()` and `log_level()`, two
    switch tables over messages nothing sends, plus the `show compat` dumps
    of `dump_vifs()` and `dump_mrt()`, which the `ipc_row()` tables
    superseded and `solo` step 7 asserts the replacement of.  A wrong line
    there misaligns a column or prints "unknown".  Not a test worth
    writing.
  - `src/trace.c` (277 lines): 0% from every lab scenario, 23% from the
    fuzz corpus.  mtrace is a message no lab sends, and the harness is the
    only thing that reaches the file at all.  Unlike `debug.c` above this
    one is a parser walking a network buffer, which is what makes its 0%
    worth something.
  - `src/dvmrp_proto.c` (26 lines): 0% from both.  Legacy interop stubs,
    and the reason half of `debug.c`'s switch arms are unreachable.
  - `src/privsep.c`: 49.3%, and that number is a floor rather than a
    finding, for the reason in the next section.


What the number does not cover
------------------------------

A `.gcda` is written by the process that exits, at a path fixed when it was
compiled, with an `open(2)`.  Three things follow, and all three are why
this file exists:

  - **The unprivileged half of a separated daemon cannot write one.**  The
    `chroot()` took that path away on every system, and on Linux `open` is
    not on the seccomp allowlist, so the half that runs every parser and
    every state machine would be killed for asking.  `COVERAGE=yes` in
    `test/lab.sh` therefore starts the daemons `--no-privsep`.  The one
    exception is the `privsep` scenario, where the split is the subject:
    it keeps it, so only its privileged half is counted -- and that half
    it then SIGKILLs, for the control below.  `src/privsep.c` reports
    what the unseparated path of every other scenario reached, and little
    of the separated one.

  - **A daemon that is killed writes nothing.**  `stop()` ends them with
    SIGTERM, which reaches `cleanup()` and `exit(0)`, but `restart_pimd()`
    uses SIGKILL on purpose -- `assert-recover` needs a router that did not
    say goodbye, or the generation ID event it is about never happens, and
    `privsep` restarts the same way for the control it ends on.  Those
    incarnations' counters are gone.

  - **A crash is a lost count too**, which cuts the other way and is worth
    knowing: a scenario that failed because pimd died reports less than the
    one that passed beside it, so read a number from a green run only.

Two more bounds that are not about pimd:

  - Lines in headers are attributed to the header, so `src/vif.h` appears
    in the table.  That is the `static inline` in it, not a mistake.

  - `src/netlink.c` and `src/routesock.c` are one file each, and only one
    of them is compiled: the report is missing whichever the measuring
    host does not build.  FreeBSD builds `routesock.c`, Linux
    `netlink.c`, and `NETLINK=yes` on FreeBSD builds the other one there.
    Neither number is the union, and the union is what a claim about
    "the RPF backend" would need.


Reading it
----------

The table is sorted by unreached lines, so the top of it is the answer to
"what does no test reach".  `coverage/<name>-uncovered.txt` has the line
ranges per file, which is what says whether a file at 40% is half a parser
nobody drives or one large error path.

Sorted by unreached lines is not sorted by what matters, and nothing in the
table can be: a line's weight is what a wrong one would cost, which gcov
does not know.  Read it in that order by hand -- the parsers first
(`pim_proto.c`, `igmp_proto.c`, `trace.c`, `config.c`, which read what a
neighbour or an operator supplies), then the kernel and socket error paths
(`kern.c`, `routesock.c`, `netlink.c`), and last the output code, where
`debug.c`'s 343 lines sit and where a wrong line misaligns a column.

A file at 0% is the interesting case, and there are two honest reasons for
one: the code is legacy that nothing runs (`src/dvmrp_proto.c`), or it is
reachable only from a message no test sends (`src/trace.c`, mtrace).  The
second is a test worth writing; the first is a line in `doc/TODO.org`.

The two tables do not share a denominator, so do not subtract them.  Only
the files a build produced counters for appear in its table, and the corpus
replay links the harnesses rather than the daemon: `main.c`, `ipc.c` and
`pimctl.c` are not in it at all, and its TOTAL is over the lines that are.
Compare the two per file, which is where the interesting answer is anyway --
`trace.c` is 0% from every lab scenario and a fifth of it from the corpus,
mtrace being a message no lab sends.

The number to compare against is the last one, not an absolute: the suite
reaches what it reaches, and what matters is that a new scenario moves it
and a refactor does not quietly lose it.  A scenario that adds nothing to
the number is not thereby worthless -- `crafted` asserts what pimd
*refuses*, which is a branch taken in code the rest of the suite already
reaches -- but it should be a deliberate answer rather than a surprise.


In CI
-----

`.github/workflows/coverage.yml` runs both builds weekly on Linux and puts
the two tables in the job summary, with the reports as an artifact.  A
workflow of its own and on a schedule for the reason `sanitize.yml` is: the
lab is long, and the per-push jobs should report without waiting for it.
`workflow_dispatch` runs it by hand, which is what to do after adding a
scenario.
