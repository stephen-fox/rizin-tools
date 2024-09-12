#!/bin/sh

# SYNOPSIS
#  library-exports.sh /path/to/library
#
# DESCRIPTION
#   library-exports.sh creates a list of function signatures for a library's
#   exported symbols using rizin. The script's output can be used to stub out
#   a proxy library.
#
# ENVIRONMENT VARIABLES
#   RZ_LIBRARY_EXPORTS_NO_TRIM: Set to 1 to disable trimming of filename
#                               and "sym." prefix

set -eu

which gojq > /dev/null
which rizin > /dev/null
which sed > /dev/null

library_file="${1}"
library_basename="${library_file##*/}"

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

sigs="$(rizin -AA -c "${cmd}" -q "${library_file}")"

if printenv RZ_LIBRARY_EXPORTS_NO_TRIM > /dev/null
then
  echo "${sigs}"
else
  echo "${sigs}" | sed -e "s/${library_basename}_//g" -e "s/sym\.//g"
fi
