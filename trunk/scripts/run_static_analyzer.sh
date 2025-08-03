#!/bin/sh

dummy_file=scan_build

rm_cache_file()
{
	test "$cache_file" = /dev/null || rm -fv "$cache_file"
}

do_configure()
{
	rm_cache_file

	scan-build ./configure --enable-debugging
	touch "$dummy_file"
}

set -eu

# import Autoconf cache file path variable
cache_file=/dev/null
for f in /usr/share/config.site /usr/local/share/config.site; do
	test -r $f && . $f
done

if [ ! -f configure ]; then
	echo "\"configure\" script not found (must run from root build directory)" \
		>&2
	exit 1
fi

trap rm_cache_file EXIT INT TERM HUP

if [ ! -f Makefile ]; then
	do_configure
elif [ ! -f $dummy_file ]; then
	echo "Project not configured for static analysis" >&2
	make distclean
	do_configure
fi

exec scan-build make "$@"

# vi: set noexpandtab sw=4 ts=4:
