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
tree as of this writing:

  - the lab suite, 23 scenarios green at `-j 12` in 7m44s on 16 cores,
    reaches **67.3%** of the 11442 instrumented lines of `src/` and `lib/`;
  - the fuzz corpus replay reaches **33.1%** of the 10060 its own build
    instruments -- fewer files, `main.c`, `ipc.c` and `pimctl.c` not being
    linked into the harnesses at all.

The instrumentation costs the labs little: the same 23 scenarios take about
seven minutes at `-j 14` without it.  What a coverage build does cost is a
scenario's margin, every assertion in the lab being a poll against a
deadline, so read a number from a green run and re-run a scenario that
tripped on its own before believing it.

The top of that table, and what it settles:

  - `src/trace.c` (277 lines): 0% from every lab scenario, 23% from the
    fuzz corpus.  mtrace is a message no lab sends, and the harness is the
    only thing that reaches the file at all.
  - `src/dvmrp_proto.c` (26 lines): 0% from both.  Legacy interop stubs.
  - `src/config.c`: 526 lines, the second largest block after
    `pim_proto.c`, and mostly single lines rather than blocks --
    allocation failures, `logit(LOG_ERR)` arms, and keywords no scenario
    writes into a `pimd.conf`.
  - `src/privsep.c`: 47.7%, and that number is a floor rather than a
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
