#
# configure.ac
#

env_cflags="$CFLAGS"

AC_INIT([libmatroska], m4_esyscmd_s([cat .version]))
AC_PREREQ([2.69])

AC_CONFIG_SRCDIR([matroska.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_REQUIRE_AUX_FILE([tap-driver.sh])

AC_CANONICAL_TARGET

dnl ensure installed files are accessible by non-root users when parent
dnl directories are created
dnl FIXME: Honor file mode creation mask for non-installation directories
MKDIR_P="build-aux/mkpath -m 0755"

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])

AS_CASE(
    [$target_os],
        [*darwin*],
            [platform=darwin],
        [*freebsd*],
            [platform=freebsd],
        [*linux*],
            [platform=linux],
        [AC_MSG_ERROR([unsupported platform], [1])]
)
AM_CONDITIONAL([APPLE], [test "$platform" = "darwin"])
AM_CONDITIONAL([FREEBSD], [test "$platform" = "freebsd"])
AM_CONDITIONAL([LINUX], [test "$platform" = "linux"])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB

AX_CHECK_COMPILE_FLAG([-std=c11], [std_flags="-std=c11"], [std_flags=])
AC_SUBST([std_flags])

warnings="-Wstrict-aliasing"

AX_CHECK_COMPILE_FLAG(
    [-Werror -Wgnu-include-next -Wnewline-eof -Wnullability-extension],
    [warnings="$warnings -Wpedantic -Wno-gnu-include-next -Wno-newline-eof"
     warnings="$warnings -Wno-nullability-extension"]
)

AC_SUBST([warnings])

AC_CHECK_PROGS([pkgcfg], [pkg-config pkgconf])

AX_LD_VERSION_SCRIPT

ebml_schema="-"
ebml_semantics_schema="-"
#ebml_schema="schemas/ebml_schema.xml"
#ebml_semantics_schema="schemas/ebml_semantics_schema.xml"

test "$ebml_schema" != "-" && ebml_schema_dep=$ebml_schema
test "$ebml_semantics_schema" != "-" \
    && ebml_semantics_schema_dep=$ebml_semantics_schema

AC_SUBST([ebml_schema])
AC_SUBST([ebml_schema_dep])

AC_SUBST([ebml_semantics_schema])
AC_SUBST([ebml_semantics_schema_dep])

AC_ARG_ENABLE([debugging],
              [  --enable-debugging      enable debugging],
              [AS_CASE(
                  [$enableval],
                      [yes],
                          [debug=true],
                      [no],
                          [debug=false],
                      [AC_MSG_ERROR([invalid "--enable-debugging" argument])]
               )
              ],
              [debug=false])
AM_CONDITIONAL([DEBUG], [test $debug = true])

AX_CHECK_COMPILE_FLAG([-Werror -fstrict-aliasing],
    [strict_aliasing="-fstrict-aliasing"],
    [strict_aliasing=]
)
AC_SUBST([strict_aliasing])

AC_CHECK_FUNCS_ONCE([strerror_l])

PKG_CHECK_MODULES([libjson], [libjson],
                  [libjson_cppflags=$libjson_CFLAGS
                   libjson_link_dep=$libjson_LIBS]
)
AC_SUBST([libjson_cppflags])
AC_SUBST([libjson_link_dep])

PKG_CHECK_MODULES([libutil], [libutil],
                  [libutil_cppflags=$libutil_CFLAGS
                   libutil_link_dep=$libutil_LIBS]
)
AC_SUBST([libutil_cppflags])
AC_SUBST([libutil_link_dep])

AS_IF(
    [test $platform = darwin],
    [xcode_dir=/Applications/Xcode.app
     platforms_dir=$xcode_dir/Contents/Developer/Platforms/MacOSX.platform
     sdk_dir=$platforms_dir/Developer/SDKs/MacOSX.sdk
     includedir_libxml2=$sdk_dir/usr/include/libxml2
     libxml2_cppflags="-I\"$includedir_libxml2\""
     libxml2_link_dep="-lxml2"
     includedir_zlib=$sdk_dir/usr/include
     zlib_cppflags="-I\"$includedir_zlib\""
     zlib_link_dep="-lz"],
    [PKG_CHECK_MODULES([libxml2], [libxml-2.0],
                       [libxml2_cppflags=$libxml2_CFLAGS
                        libxml2_link_dep=$libxml2_LIBS])
     PKG_CHECK_MODULES([zlib], [zlib],
                       [zlib_cppflags=$zlib_CFLAGS
                        zlib_link_dep=$zlib_LIBS])]
)

AC_SUBST([libxml2_cppflags])
AC_SUBST([zlib_cppflags])
AC_SUBST([libmatroska_cppflags], [""])

AC_SUBST([libxml2_link_dep])
AC_SUBST([zlib_link_dep])
AC_SUBST([libmatroska_link_dep], ["$libutil_link_dep $zlib_link_dep"])

AC_ARG_WITH([pkgconfigdir],
            [  --with-pkgconfigdir=DIR install pkg-config data in DIR],
            [pkgconfigdir="$withval"],
            [pkgconfigdir="$libdir/pkgconfig"])
AC_SUBST([pkgconfigdir])

AC_SUBST([lm_cur], [0])
AC_SUBST([lm_age], [0])
AC_SUBST([lm_rev], [0])

dnl FIXME: Later, only prevent Autoconf from adding "-g -O2" to CFLAGS
CFLAGS="$env_cflags"

AC_CONFIG_FILES([Makefile include/Makefile libmatroska.pc])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT

dnl Pass sed output to cat in the following to write output in larger blocks,
dnl reducing the needed time to run the commands
dnl FIXME: Replace with wrapper script or utility
postlink_cmds=:
AS_IF(
    [test $platform = darwin],
    [libpath="$(pwd | sed -e 's#/#\\/#g')\/.libs\/libmatroska.dylib"
     postlink_cmds="${postlink_cmds}; scripts\/fix_up_linking_os_x.sh"
     postlink_cmds="$postlink_cmds @OUTPUT@ $libpath"]
)
lt=libtool
sed_edit_expr="s/postlink_cmds=\"\"/postlink_cmds=\"$postlink_cmds\"/"
sed -e "$sed_edit_expr" $lt | cat >${lt}.new \
    && mv -f ${lt}.new $lt \
    && chmod +x $lt

cat <<-EOF

$PACKAGE_NAME configuration

               Compiler: $CC

              Debugging: $debug

    Installation prefix: $prefix

EOF

dnl vi: set expandtab sw=4 ts=4:
