dnl
dnl matroska_schema.m4
dnl

define(`push', `define(`$1', defn(`$1')/$2)')
define(`pop', `define(`$1', patsubst(defn(`$1'), `/[^/]*$', `'))')
define(`next', `pop(`$1')push(`$1', $2)')

define(`bname', `patsubst(`$1', patsubst(`$1', `[^/]*$', `'), `')')

dnl vi: set noexpandtab sw=4 ts=4:
