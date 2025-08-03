#!/bin/sh

get_cur_lib_path()
{
	otool -L "$1" | sed -n \
		-e '1d' \
		-e "s/$2/$2/; t found" \
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

while read -r line; do
	if [ "$file" = "$line" ]; then
		curpath=$(get_cur_lib_path "$file" "libmatroska")
		test -z "$curpath" && exit 0
		replace_path "$curpath" "$lib" "$file"
		exit $?
	fi
done <<-'EOF'
	element_test
	mkv_cat
	mkv_dump
	mkv_ls
	mkv_write
	vint_test
EOF

# vi: set noexpandtab sw=4 ts=4:
