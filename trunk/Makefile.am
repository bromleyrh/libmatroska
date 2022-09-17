##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include

EXTRA_DIST = bootstrap build-aux doc libmatroskalite.map libmatroskalite.pc.in \
	lsmkv schemas .version

build_date = "$(shell date)"
build_vers = "$(shell git rev-parse HEAD)"

debug_cppflags_debug =
debug_cflags_debug = -ggdb3 -O0

debug_cppflags_ndebug = -DNDEBUG
debug_cflags_ndebug = -O2

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

noinst_HEADERS = common.h ebml.h element.h parser.h parser_defs.h radix_tree.h \
	util.h vint.h zlib_stream.h

BUILT_SOURCES = ebml_schema.h matroska_schema.h matroska_semantics.h version.c

CLEANFILES = ebml_schema.h matroska_schema.h matroska_semantics.h version.c

build_date_str = "build_date=$(build_date)"
build_vers_str = "build_git_commit_id=$(build_vers)"

ebml_schema = schemas/ebml_schema.xml
ebml_semantics_schema = schemas/ebml_semantics_schema.xml

ebml_schema.h: schema_parse $(ebml_schema) schemas/ebml.m4
	m4 schemas/ebml.m4 | ./schema_parse $(ebml_schema) ebml >|$@

matroska_schema.h: schema_parse $(ebml_schema) schemas/matroska.m4
	m4 schemas/matroska.m4 | ./schema_parse $(ebml_schema) matroska >|$@

matroska_semantics.h: schema_parse $(ebml_semantics_schema) \
	schemas/matroska_semantics.m4
	m4 schemas/matroska_semantics.m4 \
		| ./schema_parse $(ebml_semantics_schema) matroska_semantics >|$@

version.c:
	echo "const char build_date[] = \"$(build_date_str)\";" >|$@
	echo "const char build_git_commit_id[] = \"$(build_vers_str)\";" >>$@

lib_LTLIBRARIES = libmatroskalite.la

matroskalite_link = $(abs_builddir)/.libs/libmatroskalite.$(sosuf)
matroskalite_link_dep = @libmatroskalite_link_dep@

if LD_VERSION_SCRIPT
version_script = -Wl,--version-script=libmatroskalite.map
endif

bin_PROGRAMS = mkv_dump zlib_cat

mkv_dump_SOURCES = mkv_dump.c
mkv_dump_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude @libutil_cppflags@
mkv_dump_CFLAGS = $(AM_CFLAGS)
mkv_dump_LDADD = $(matroskalite_link) $(matroskalite_link_dep) \
	@libutil_link_dep@
mkv_dump_LDFLAGS = -rpath @abs_top_builddir@/.libs
mkv_dump_DEPENDENCIES = libmatroskalite.la

zlib_cat_SOURCES = zlib_cat.c zlib_stream.c
zlib_cat_CPPFLAGS = $(AM_CPPFLAGS) @zlib_cppflags@
zlib_cat_CFLAGS = $(AM_CFLAGS)
zlib_cat_LDADD = @zlib_link_dep@

bin_SCRIPTS = lsmkv

noinst_PROGRAMS = schema_parse

schema_parse_SOURCES = element.c radix_tree.c schema_parse.c vint.c
schema_parse_CPPFLAGS = $(AM_CPPFLAGS) @libutil_cppflags@ @libxml2_cppflags@
schema_parse_CFLAGS = $(AM_CFLAGS)
schema_parse_LDADD = @libutil_link_dep@ @libxml2_link_dep@

libmatroskalite_la_SOURCES = ebml.c element.c matroska.c parser.c util.c \
	vint.c zlib_stream.c
libmatroskalite_la_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude @zlib_cppflags@
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

include scripts/Makefile.am

install-exec-hook:
	if [ `uname` = Darwin ]; then \
		chmod -h 0755 $(libdir)/libmatroskalite.$(sosuf); \
	fi
	@if ldc=`which ldconfig 2>/dev/null` && test -x ${ldc}; then \
		echo "Regenerating runtime linker cache"; \
		ldconfig || true; \
	fi
	@echo
	@echo "Note: The path \"$(pkgconfigdir)\" must be added to"
	@echo "PKG_CONFIG_PATH in order to build dependent modules"
	@echo

## vi: set noexpandtab sw=4 ts=4:
