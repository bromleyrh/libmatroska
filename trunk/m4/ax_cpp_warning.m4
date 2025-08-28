#
# ax_cpp_warning.m4
#

AC_DEFUN([_AX_CPP_WARNING],
    [_cv=ax_cv_cpp_warning_w$2
     _warn="-W$1"
     AC_MSG_CHECKING([for "$_warn" C compiler warning flag])
     AC_CACHE_VAL([$_cv],
        [old_CPPFLAGS=$CPPFLAGS
         CPPFLAGS="$_warn"
         AC_PREPROC_IFELSE([AC_LANG_SOURCE([[int main(void) { return 0; }]])],
             [eval $_cv=yes],
             [eval $_cv=no]
         )
         CPPFLAGS=$old_CPPFLAGS
         unset old_CPPFLAGS
        ]
     )
     AC_MSG_RESULT([$(eval printf "%s" '$'$_cv)])
     AS_IF(
        [test "x$(eval printf "%s" '$'$_cv)" = "xyes"],
        [_pragma="GCC_PRAGMA(diagnostic ignored \"$_warn\")"]
     )
     AC_DEFINE_UNQUOTED([_GCC_DIAGNOSTIC_IGNORED_$2],
        [$_pragma],
        [Define to the CPP pragma for suppressing `-W$1'.]
     )
     unset _cv _pragma _warn
    ]
)

AC_DEFUN([AX_CPP_WARNING], [_AX_CPP_WARNING($1, m4_bpatsubst($1, [-], [_]))])

# vi: set expandtab sw=4 ts=4:
