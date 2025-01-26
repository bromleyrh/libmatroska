#
# ax_ld_version_script.m4
#

AC_DEFUN([AX_LD_VERSION_SCRIPT],
    [AC_CACHE_CHECK([for ld version script support],
        [ax_cv_ld_version_script],
        [AS_IF(
            [ld --help | grep -- --version-script >/dev/null 2>/dev/null],
            [ax_cv_ld_version_script=yes]
         )
        ]
     )
     AM_CONDITIONAL([LD_VERSION_SCRIPT],
         [test "x$ax_cv_ld_version_script" = "xyes"])
    ]
)

# vi: set expandtab sw=4 ts=4:
