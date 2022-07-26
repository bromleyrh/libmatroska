#
# configure.ac
#

env_cflags="$CFLAGS"

AC_INIT([libmatroskalite], m4_esyscmd_s([cat .version]))
AC_PREREQ([2.69])

AC_CONFIG_SRCDIR([matroska.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET

dnl ensure installed files are accessible by non-root users when parent
dnl directories are created
dnl FIXME: Honor file mode creation mask for non-installation directories
MKDIR_P="build-aux/mkpath -m 0755"

AM_INIT_AUTOMAKE([foreign no-define subdir-objects])
AM_SILENT_RULES([yes])
LT_INIT([disable-static])

case $target_os in
    *darwin*)
        platform=darwin;;
    *freebsd*)
        platform=freebsd;;
    *linux*)
        platform=linux;;
    *)
        AC_MSG_ERROR([unsupported platform], [1]);;
esac
AM_CONDITIONAL([APPLE], [test "x$platform" = "xdarwin"])
AM_CONDITIONAL([FREEBSD], [test "x$platform" = "xfreebsd"])
AM_CONDITIONAL([LINUX], [test "x$platform" = "xlinux"])

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_RANLIB

AC_CHECK_PROGS([pkgcfg], [pkg-config pkgconf])

AX_LD_VERSION_SCRIPT

AC_ARG_ENABLE([debugging],
              [  --enable-debugging      enable debugging],
              [case "$enableval" in
                   yes)
                       debug=true;;
                   no)
                       debug=false;;
                   *)
                       AC_MSG_ERROR([invalid "--enable-debugging" argument]);;
               esac],
              [debug=false])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

AC_CHECK_FUNCS_ONCE([fls])

PKG_CHECK_MODULES([libutil], [libutil],
                  [libutil_cppflags=$libutil_CFLAGS
                   libutil_link_dep=$libutil_LIBS]
)
AC_SUBST([libutil_cppflags])
AC_SUBST([libutil_link_dep])

AS_IF(
    [test x$platform = xdarwin],
    [xcode_dir=/Applications/Xcode.app
     platforms_dir=$xcode_dir/Contents/Developer/Platforms/MacOSX.platform
     sdk_dir=$platforms_dir/Developer/SDKs/MacOSX.sdk
     includedir_libxml2=$sdk_dir/usr/include/libxml2
     libxml2_cppflags="-I\"$includedir_libxml2\""
     libxml2_link_dep="-lxml2"],
    [AC_MSG_ERROR([unsupported platform], [1])]
)

AC_SUBST([libxml2_cppflags])
AC_SUBST([libmatroskalite_cppflags], [""])

AC_SUBST([libxml2_link_dep])
AC_SUBST([libmatroskalite_link_dep], [""])

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

AC_CONFIG_FILES([Makefile include/Makefile libmatroskalite.pc])
AC_CONFIG_HEADERS([config.h])
AC_OUTPUT

dnl Pass sed output to cat in the following to write output in larger blocks,
dnl reducing the needed time to run the commands
dnl FIXME: Replace with wrapper script or utility
postlink_cmds=:
AS_IF(
    [test x$platform = xdarwin],
    [libpath="$(pwd | sed -e 's/\//\\\//g')\/.libs\/libn.dylib"
     postlink_cmds="${postlink_cmds}; scripts\/fix_up_linking_os_x.sh"
     postlink_cmds="$postlink_cmds @OUTPUT@ $libpath"]
)
lt=libtool
sed_edit_expr="s/postlink_cmds=\"\"/postlink_cmds=\"$postlink_cmds\"/"
sed -e "$sed_edit_expr" $lt | cat > ${lt}.new \
    && mv -f ${lt}.new $lt \
    && chmod +x $lt

cat <<- EOF

$PACKAGE_NAME configuration

               Compiler: $CC

              Debugging: $debug

    Installation prefix: $prefix

EOF

dnl vi: set expandtab sw=4 ts=4:
