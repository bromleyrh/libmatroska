#!/bin/sh

test_driver=${BUILDDIR:?}/build-aux/test-driver

esc_str()
{
	sed "s/'/'\\\\''/g; 1s/^/'/; \$s/\$/'/"
}

add_to_args()
{
	if [ -n "$args" ]; then
		args="$(printf "%s %s" "$args" "$(printf %s "$1" | esc_str)")"
	else
		args="$(printf %s "$1" | esc_str)"
	fi
}

set -eu

if [ "${TESTS_SKIP:-}" = 1 ]; then
	args=
	if [ $# -gt 1 ]; then
		i=1
		n=$#
		while true; do
			add_to_args "$1"
			i=$((i+1))
			test $i -eq $n && break
			shift
		done
	fi
	add_to_args "sh"
	add_to_args "-c"
	add_to_args "exit 77"
	eval "set -- $args"
fi

exec "$test_driver" "$@"

# vi: set noexpandtab sw=4 ts=4:
