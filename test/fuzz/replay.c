/*
 * replay - run a harness over files, with no fuzzer in the picture
 *
 * Copyright (c) 2026  Olivier Cochard-Labbe <olivier@cochard.me>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 * The same entry point libFuzzer calls, driven by a main() of two dozen
 * lines: every argument is a file, and every file is handed to the harness
 * once, in order.  A directory argument is walked one level deep, so a
 * whole corpus is one argument.
 *
 * This is what makes a corpus a test rather than a pile of inputs.  It
 * needs no clang, no libFuzzer, no root and no network, so `make check`
 * runs it everywhere and every crasher the fuzzer ever found stays found:
 * commit the input, and the next build that reintroduces the bug fails in
 * the test suite rather than the next time somebody remembers to fuzz.
 *
 * Exit status is the harness's own behaviour -- it aborts, or it does not.
 * Under a sanitizer that is the whole verdict; without one it is only "did
 * not crash", which is why the CI job builds it with both of them.
 */

#include <dirent.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define REPLAY_MAX_SIZE	(1024 * 1024)

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int replay_file(const char *path)
{
	uint8_t *buf;
	size_t len;
	FILE *fp;
	long size;

	fp = fopen(path, "rb");
	if (!fp) {
		warn("cannot open %s", path);
		return 1;
	}

	if (fseek(fp, 0, SEEK_END) == -1 || (size = ftell(fp)) < 0) {
		warn("cannot size %s", path);
		fclose(fp);
		return 1;
	}
	rewind(fp);

	if (size > REPLAY_MAX_SIZE) {
		warnx("%s is %ld bytes, skipping", path, size);
		fclose(fp);
		return 1;
	}

	/* One byte over, so a zero length file still has something to free
	 * and fread() of 0 is not asked to write into NULL */
	buf = malloc((size_t)size + 1);
	if (!buf) {
		warnx("out of memory for %s", path);
		fclose(fp);
		return 1;
	}

	len = fread(buf, 1, (size_t)size, fp);
	fclose(fp);

	printf("  %s (%zu bytes)\n", path, len);
	LLVMFuzzerTestOneInput(buf, len);

	free(buf);

	return 0;
}

static int replay_dir(const char *path)
{
	char file[4096];
	struct dirent *de;
	int rc = 0;
	DIR *dir;

	dir = opendir(path);
	if (!dir) {
		warn("cannot open directory %s", path);
		return 1;
	}

	while ((de = readdir(dir))) {
		struct stat st;

		if (de->d_name[0] == '.')
			continue;

		snprintf(file, sizeof(file), "%s/%s", path, de->d_name);
		if (stat(file, &st) == -1 || !S_ISREG(st.st_mode))
			continue;

		rc |= replay_file(file);
	}

	closedir(dir);

	return rc;
}

int main(int argc, char *argv[])
{
	int i, rc = 0;

	if (argc < 2) {
		fprintf(stderr, "usage: %s FILE|DIR ...\n", argv[0]);
		return 1;
	}

	LLVMFuzzerInitialize(&argc, &argv);

	for (i = 1; i < argc; i++) {
		struct stat st;

		if (stat(argv[i], &st) == -1) {
			warn("cannot stat %s", argv[i]);
			rc = 1;
			continue;
		}

		if (S_ISDIR(st.st_mode))
			rc |= replay_dir(argv[i]);
		else
			rc |= replay_file(argv[i]);
	}

	return rc;
}
