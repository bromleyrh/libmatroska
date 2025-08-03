##
## Makefile.am
##

## Process this file with automake to produce Makefile.in

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include

EXTRA_DIST = bootstrap build-aux libmatroska.map libmatroska.pc.in lsmkv \
	mkv_catalog_obj.idl pipefail schema_parse_cached schemas .version

build_date = "$(shell date)"
build_vers = "$(shell git rev-parse HEAD)"

debug_cppflags_debug =
debug_cflags_debug = -ggdb3 -O0

debug_cppflags_ndebug =
debug_cflags_ndebug = -O2

std_cppflags = -D_XOPEN_SOURCE=700
std_cflags = @std_flags@

AM_CPPFLAGS = $(defines) $(std_cppflags)
AM_CFLAGS = $(std_cflags) -pipe -Wall -Wextra @warnings@ @strict_aliasing@

if DEBUG
AM_CPPFLAGS += $(debug_cppflags_debug)
AM_CFLAGS += $(debug_cflags_debug)
else
AM_CPPFLAGS += $(debug_cppflags_ndebug)
AM_CFLAGS += $(debug_cflags_ndebug)
endif

if APPLE
sosuf = dylib
else
sosuf = so
endif

pkgconfigdir = @pkgconfigdir@

pkgconfig_DATA = libmatroska.pc

$(pkgconfig_DATA): config.status

noinst_HEADERS = common.h debug.h ebml.h element.h parser.h parser_defs.h \
	radix_tree.h util.h vint.h zlib_stream.h

BUILT_SOURCES = ebml_schema.h matroska_schema.h matroska_semantics.h \
	mkv_catalog_obj.h version.c

CLEANFILES = ebml_schema.h matroska_schema.h matroska_semantics.h \
	mkv_catalog_obj.h version.c

build_date_str = "build_date=$(build_date)"
build_vers_str = "build_git_commit_id=$(build_vers)"

ebml_schema = @ebml_schema@
ebml_schema_dep = @ebml_schema_dep@

ebml_semantics_schema = @ebml_semantics_schema@
ebml_semantics_schema_dep = @ebml_semantics_schema_dep@

ebml_schema.h: schema_parse $(ebml_schema_dep) schemas/ebml.m4
	./schema_parse_cached schemas/ebml.m4 $(ebml_schema) ebml "$@"

matroska_schema.h: schema_parse $(ebml_schema_dep) schemas/matroska.m4
	./schema_parse_cached schemas/matroska.m4 $(ebml_schema) matroska "$@"

matroska_semantics.h: schema_parse $(ebml_semantics_schema_dep) \
	schemas/matroska_semantics.m4
	./schema_parse_cached schemas/matroska_semantics.m4 \
		$(ebml_semantics_schema) matroska_semantics "$@"

mkv_catalog_obj.h: mkv_catalog_obj.idl
	idlc <"$^" >"$@"

version.c:
	echo "const char build_date[] = \"$(build_date_str)\";" >|"$@"
	echo "const char build_git_commit_id[] = \"$(build_vers_str)\";" >>"$@"

lib_LTLIBRARIES = libmatroska.la

matroska_link = $(abs_builddir)/.libs/libmatroska.$(sosuf)
matroska_link_dep = @libmatroska_link_dep@

if LD_VERSION_SCRIPT
version_script = -Wl,--version-script=libmatroska.map
endif

bin_PROGRAMS = mkv_cat mkv_catalog mkv_dump mkv_join mkv_ls mkv_write zlib_cat

mkv_cat_SOURCES = mkv_cat.c
mkv_cat_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude @libutil_cppflags@
mkv_cat_CFLAGS = $(AM_CFLAGS)
mkv_cat_LDADD = $(matroska_link) $(matroska_link_dep) @libutil_link_dep@
mkv_cat_LDFLAGS = -rpath @abs_top_builddir@/.libs
mkv_cat_DEPENDENCIES = libmatroska.la

mkv_catalog_SOURCES = debug.c mkv_catalog.c util.c
mkv_catalog_CPPFLAGS = $(AM_CPPFLAGS) @libjson_cppflags@ @libutil_cppflags@
mkv_catalog_CFLAGS = $(AM_CFLAGS)
mkv_catalog_LDADD = @libjson_link_dep@ @libutil_link_dep@

mkv_dump_SOURCES = mkv_dump.c
mkv_dump_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude @libutil_cppflags@
mkv_dump_CFLAGS = $(AM_CFLAGS)
mkv_dump_LDADD = $(matroska_link) $(matroska_link_dep) \
	@libutil_link_dep@
mkv_dump_LDFLAGS = -rpath @abs_top_builddir@/.libs
mkv_dump_DEPENDENCIES = libmatroska.la

mkv_join_SOURCES = debug.c mkv_join.c util.c
mkv_join_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude @libjson_cppflags@
mkv_join_CFLAGS = $(AM_CFLAGS)
mkv_join_LDADD = @libjson_link_dep@

mkv_ls_SOURCES = mkv_ls.c
mkv_ls_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude @libjson_cppflags@ @libutil_cppflags@
mkv_ls_CFLAGS = $(AM_CFLAGS)
mkv_ls_LDADD = $(matroska_link) $(matroska_link_dep) \
	@libjson_link_dep@ @libutil_link_dep@
mkv_ls_LDFLAGS = -rpath @abs_top_builddir@/.libs
mkv_ls_DEPENDENCIES = libmatroska.la

mkv_write_SOURCES = mkv_write.c strptime.c util.c
mkv_write_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude @libjson_cppflags@ \
	@libutil_cppflags@
mkv_write_CFLAGS = $(AM_CFLAGS)
mkv_write_LDADD = $(matroska_link) $(matroska_link_dep) \
	@libjson_link_dep@ @libutil_link_dep@
mkv_write_LDFLAGS = -rpath @abs_top_builddir@/.libs
mkv_write_DEPENDENCIES = libmatroska.la

zlib_cat_SOURCES = debug.c util.c zlib_cat.c zlib_stream.c
zlib_cat_CPPFLAGS = $(AM_CPPFLAGS) @libutil_cppflags@ @zlib_cppflags@
zlib_cat_CFLAGS = $(AM_CFLAGS)
zlib_cat_LDADD = @libutil_link_dep@ @zlib_link_dep@

bin_SCRIPTS = lsmkv

noinst_PROGRAMS = schema_parse

schema_parse_SOURCES = debug.c element.c radix_tree.c schema_parse.c util.c \
	vint.c
schema_parse_CPPFLAGS = $(AM_CPPFLAGS) @libutil_cppflags@ @libxml2_cppflags@
schema_parse_CFLAGS = $(AM_CFLAGS)
schema_parse_LDADD = @libutil_link_dep@ @libxml2_link_dep@

libmatroska_la_SOURCES = debug.c ebml.c element.c matroska.c parser.c util.c \
	vint.c zlib_stream.c
libmatroska_la_CPPFLAGS = $(AM_CPPFLAGS) -Iinclude @zlib_cppflags@
libmatroska_la_CFLAGS = $(AM_CFLAGS)
libmatroska_la_LDFLAGS = -version-info @lm_cur@:@lm_rev@:@lm_age@ \
	$(version_script)

check_PROGRAMS =
TESTS =

include scripts/Makefile.am
include tests/Makefile.am
include third_party/Makefile.am

install-exec-hook:
	if [ `uname` = Darwin ]; then \
		chmod -h 0755 "$(libdir)/libmatroska.$(sosuf)"; \
	fi
	@if ldc=`which ldconfig 2>/dev/null` && test -x $$ldc; then \
		echo "Regenerating runtime linker cache"; \
		ldconfig || true; \
	fi
	@echo
	@echo "Note: The path \"$(pkgconfigdir)\" must be added to"
	@echo "PKG_CONFIG_PATH in order to build dependent modules"
	@echo

distclean-local:
	-rm -f scan_build

## vi: set noexpandtab sw=4 ts=4:
