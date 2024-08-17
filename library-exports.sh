#!/bin/sh

set -eu

which gojq > /dev/null
which rizin > /dev/null

library_file="${1}"
cmd=''

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
