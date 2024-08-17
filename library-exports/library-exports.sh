#!/bin/sh

# library-exports.sh gets the function signatures for a library's
# exported symbols:
#
# usage: library-exports.sh /path/to/library

set -eu

which gojq > /dev/null
which rizin > /dev/null

library_file="${1}"
cmd=''

# Get exported symbols from library and build list of addresses to seek to
# and subsequently get function signature.
#
# E.g., "s 268440336; afs;s 268440704; afs;s 268441392".
cmd="$(rz-bin -Ej "${library_file}" \
  | gojq -r '.exports.[] | "\(.name) \(.vaddr)"' \
  | {
  while read l
  do
    name=${l% *}
    offset=${l##* }
    cmd="${cmd}s ${offset}; afs;"
  done
  echo "${cmd}"
})"

rizin -AA -c "${cmd}" -q "${library_file}"
