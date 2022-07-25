dnl
dnl matroska_schema.m4
dnl

define(`push', `define(`$1', defn(`$1')/$2)')
define(`pop', `define(`$1', patsubst(defn(`$1'), `/[^/]*$', `'))')
define(`next', `pop(`$1')push(`$1', $2)')

define(`_rm_bname', `patsubst(`$1', `[^/]*$', `')')
define(`_rm_dirname', `patsubst(`$1', _esc_regex(_rm_bname(`$1')), `')')

define(`_esc_regex', `patsubst(`$1', `\+', `\\\+')')

define(`_canonicalize_name', `patsubst(`$1', `^+', `')')

define(`bname', `_canonicalize_name(_rm_dirname(`$1'))')

dnl vi: set noexpandtab sw=4 ts=4:
