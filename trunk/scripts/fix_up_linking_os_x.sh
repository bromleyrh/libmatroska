#!/bin/sh

get_cur_libmatroska_path()
{
	otool -L "$1" | sed -n \
		-e '1d' \
		-e 's/libmatroska/libmatroska/; t found' \
		-e 'b' \
		-e ':found' \
		-e 's/^[[:space:]]*//' \
		-e 's/ (compatibility version .*, current version .*)$//' \
		-e 'p'
}

replace_path()
{
	install_name_tool -change "$@"
}

set -eu

file=$1
lib=$2

set -- "element_test" "mkv_cat" "mkv_dump" "mkv_ls" "mkv_write" "vint_test"

for i; do
	if [ "$file" = "$i" ]; then
		curpath=$(get_cur_libmatroska_path "$file")
		test -z "$curpath" && exit 0
		replace_path "$curpath" "$lib" "$file"
		exit $?
	fi
done

# vi: set noexpandtab sw=4 ts=4:
