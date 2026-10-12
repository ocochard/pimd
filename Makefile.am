SUBDIRS        = src include man
if ENABLE_TEST
SUBDIRS       += test
endif

# Installed and shipped; the rest of doc/ and rules/ only shipped
dist_doc_DATA  = README.md ChangeLog.md LICENSE doc/LICENSE.mrouted pimd.conf
EXTRA_DIST     = doc/AUTHORS doc/CREDITS doc/FAQ.md doc/INSTALL.md		\
		 doc/README-config.md doc/README-coverage.md			\
		 doc/README-debug.md doc/README.config.jp			\
		 doc/TODO.org doc/rfc7761-compliance.md			\
		 doc/security-review-prompt.md				\
		 rules/security.cocci rules/control.c rules/run.sh

if SYSTEMD
systemd_DATA   = pimd.service
endif

# distcheck installs as a user, so the unit goes under its install tree
DISTCHECK_CONFIGURE_FLAGS = --with-systemd=$$dc_install_base/lib/systemd/system

## Build a release: refuse a version that has no git tag, then distcheck
## and write the checksums beside the tarball
release:
	@git rev-parse -q --verify "refs/tags/$(PACKAGE_VERSION)" >/dev/null || \
		{ echo "No git tag $(PACKAGE_VERSION), not releasing" >&2; exit 1; }
	$(MAKE) $(AM_MAKEFLAGS) distcheck
	@for f in $(DIST_ARCHIVES); do				\
		md5sum    $$f > $$f.md5    &&			\
		sha256sum $$f > $$f.sha256 || exit 1;		\
	done

.PHONY: release
