#!/bin/sh

get_cur_libmatroskalite_path()
{
	otool -L "$1" | tail -n +2 | grep libmatroskalite \
		| sed 's/ (compatibility version .*, current version .*)$//' | cut -f 2-
}

replace_path()
{
	install_name_tool -change "$@"
}

file=$1
lib=$2

set -- "element_test" "mkv_cat" "mkv_dump" "mkv_ls" "mkv_write" "vint_test"

for i; do
	if [ "$file" = "$i" ]; then
		curpath=$(get_cur_libmatroskalite_path "$file")
		test -z "$curpath" && exit 0
		replace_path "$curpath" "$lib" "$file"
		exit $?
	fi
done

# vi: set noexpandtab sw=4 ts=4:
