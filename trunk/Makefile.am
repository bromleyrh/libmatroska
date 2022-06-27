##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include

EXTRA_DIST = bootstrap build-aux libmatroskalite.map libmatroskalite.pc.in \
	matroska_schema.xml .version

build_date = "$(shell date)"
build_vers = "$(shell git rev-parse HEAD)"

debug_cppflags_debug =
debug_cflags_debug = -ggdb3 -O0

if DEBUG
AM_CPPFLAGS = $(defines) $(debug_cppflags_debug)
AM_CFLAGS = $(debug_cflags_debug) -pipe -Wall -Wextra
else
AM_CPPFLAGS = $(defines) $(debug_cppflags_ndebug)
AM_CFLAGS = $(debug_cflags_ndebug) -pipe -Wall -Wextra
endif

if APPLE
sosuf = dylib
else
sosuf = so
endif

pkgconfigdir = @pkgconfigdir@

pkgconfig_DATA = libmatroskalite.pc

$(pkgconfig_DATA): config.status

noinst_HEADERS = common.h element.h util.h vint.h

BUILT_SOURCES = version.c

CLEANFILES = version.c

build_date_str = "build_date=$(build_date)"
build_vers_str = "build_git_commit_id=$(build_vers)"

version.c:
	echo "const char build_date[] = \"$(build_date_str)\";" >|$@
	echo "const char build_git_commit_id[] = \"$(build_vers_str)\";" >>$@

lib_LTLIBRARIES = libmatroskalite.la

matroskalite_link = $(abs_builddir)/.libs/libmatroskalite.$(sosuf)
matroskalite_link_dep = @libmatroskalite_link_dep@

if LD_VERSION_SCRIPT
version_script = -Wl,--version-script=libmatroskalite.map
endif

libmatroskalite_la_SOURCES = element.c matroska.c util.c vint.c
libmatroskalite_la_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude
libmatroskalite_la_CFLAGS = $(AM_CFLAGS)
libmatroskalite_la_LDFLAGS = -version-info @lm_cur@:@lm_rev@:@lm_age@ \
	$(version_script)

check_PROGRAMS = element_test vint_test

element_test_SOURCES = element_test.c
element_test_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude
element_test_CFLAGS = $(AM_CFLAGS)
element_test_LDADD = $(matroskalite_link) $(matroskalite_link_dep)
element_test_LDFLAGS = -rpath @abs_top_builddir@/.libs
element_test_DEPENDENCIES = libmatroskalite.la

vint_test_SOURCES = vint_test.c
vint_test_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude
vint_test_CFLAGS = $(AM_CFLAGS)
vint_test_LDADD = $(matroskalite_link) $(matroskalite_link_dep)
vint_test_LDFLAGS = -rpath @abs_top_builddir@/.libs
vint_test_DEPENDENCIES = libmatroskalite.la

install-exec-hook:
	@if ldc=`which ldconfig 2>/dev/null` && test -x ${ldc}; then \
		echo "Regenerating runtime linker cache"; \
		ldconfig || true; \
	fi
	@echo
	@echo "Note: The path \"$(pkgconfigdir)\" must be added to"
	@echo "PKG_CONFIG_PATH in order to build dependent modules"
	@echo

## vi: set noexpandtab sw=4 ts=4:
