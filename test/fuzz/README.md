Fuzz harnesses
==============

The parsers of pimd, called in-process with generated input, under the
sanitizers.  What each harness is and what it takes care of is in the
header comment of its own file; this is the map.

| Harness            | Entry point                                          | Corpus              |
|--------------------|------------------------------------------------------|---------------------|
| `fuzz_config.c`    | `config_phyints_from_file()`, `config_vifs_from_file()` | `corpus/config/` |

`stubs.c` supplies what `main.c` would have defined, since a harness brings
its own `main()`, and `replay.c` is a `main()` of its own for builds without
libFuzzer: it hands every file it is given to the harness once, which is how
`make check` turns the corpus into a regression test through
`../fuzz-corpus.sh`.

Building and running
--------------------

```sh
./configure --enable-fuzz CC=clang					\
    CFLAGS="-g -O1 -fno-omit-frame-pointer -fno-strict-aliasing		\
            -fsanitize=address,undefined"				\
    LDFLAGS="-fsanitize=address,undefined"
make
test/fuzz_config -max_len=4096 test/fuzz/corpus/config		# hunt
make check							# replay
```

`--enable-fuzz` implies `--disable-exit-on-error`, because `logit(LOG_ERR)`
calls `exit(-1)` and a fuzzer reads that as a crash on the first input pimd
merely refuses. It also implies `--enable-test`, test/ being where this
lives. Without clang only the replay driver is built; `configure` says which
in its summary.

A find leaves `crash-<sha1>` in the working directory. Replay it with
`test/fuzz_config_replay crash-<sha1>`, fix the bug, then commit the file
into `corpus/config/` so it is asserted from then on. Crashers are what this
directory is for; a hunt's own corpus is not committed, and does not need to
be. The seeds here are the readable ones, one per shape of configuration, and
a full corpus rebuilds from them fast:

```sh
test/fuzz_config -max_len=4096 -max_total_time=900 work/          # a hunt
test/fuzz_config -merge=1 -max_len=4096 minimized/ work/          # the useful part of it
```

Measured on this tree: fifteen minutes of one process reached 743 edges of
`config.c`, and `-merge=1` reduced what it kept to 175 files of 88K. Keep
that outside the repository unless something in it is worth asserting.

Leak checking is off by default (`ASAN_OPTIONS=detect_leaks=1` asks for it,
Linux only). The harnesses free what a parse allocates, but pimd itself
keeps some of its configuration until exit, so a leak report needs reading
rather than believing.
