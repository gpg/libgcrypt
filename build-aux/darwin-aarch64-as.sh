#!/bin/sh
# Assembler wrapper for AArch64 Darwin.
# Copyright (C) 2026 Jussi Kivilinna <jussi.kivilinna@iki.fi>
#
# This file is part of Libgcrypt.
#
# Libgcrypt is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# Libgcrypt is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <http://www.gnu.org/licenses/>.

# Darwin assembler uses ';' as comment character, treats only 'L' prefixed
# labels as assembler local and C symbols have '_' prefix.
#
# Run C preprocessor on the .S source, then split ';' separated
# statements to separate lines, convert '.L' labels to 'L' and add
# prefix to _gcry symbols, and assemble the result.
#
# Usage: darwin-aarch64-as.sh CC [CCFLAGS...] ARGS...

# Preprocess only: '-c' becomes '-E' and output goes to "$pp".
run_cpp ()
{
  n=$#
  skip=
  for a in "$@"; do
    if test -n "$skip"; then
      skip=
      a="$pp"
    else
      case "$a" in
        -c) a=-E ;;
        -o) skip=1 ;;
      esac
    fi
    set -- "$@" "$a"
  done
  shift $n
  "$@"
}

# Assemble "$asm" in place of "$src", without dependency generation.
run_as ()
{
  n=$#
  skip=
  for a in "$@"; do
    if test -n "$skip"; then
      skip=
      continue
    fi
    case "$a" in
      -MT|-MF|-MQ) skip=1; continue ;;
      -MD|-MMD|-MP) continue ;;
      "$src") a="$asm" ;;
    esac
    set -- "$@" "$a"
  done
  shift $n
  "$@"
}

# Find .S source and output object; pass through non-.S compiles as is.
src=
out=
prev=
for a in "$@"; do
  case "$prev" in
    -o) out="$a" ;;
  esac
  case "$a" in
    *.S) src="$a" ;;
  esac
  prev="$a"
done

if test -z "$src"; then
  exec "$@"
fi

# Place converted source next to output object, as libtool compiles
# PIC and non-PIC objects to separate directories.
base="${src##*/}"
if test -n "$out"; then
  asm="$(dirname "$out")/${base%.S}-darwin.s"
else
  asm="${base%.S}-darwin.s"
fi
pp="$asm.i"

trap 'rm -f "$pp"' EXIT

run_cpp "$@" || exit 1

# Convert to Darwin syntax
#  * ; separator to newline
#  * .L local symbol prefix to L
#  * _gcry_ global symbol prefix to __gcry_
tr ';' '\n' < "$pp" | \
  sed -e 's/^\.L/L/' \
      -e 's/\([^A-Za-z0-9_.]\)\.L/\1L/g' \
      -e 's/^_gcry_/__gcry_/' \
      -e 's/\([^A-Za-z0-9_]\)_gcry_/\1__gcry_/g' \
  > "$asm" || exit 1

run_as "$@"
