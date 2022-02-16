#! /bin/sh

#
# genhmac.sh - Build tool to generate hmac hash
#
# Copyright (C) 2022  g10 Code GmbH
#
# This file is part of libgcrypt.
#
# libgcrypt is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# libgcrypt is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, see <https://www.gnu.org/licenses/>.
#

set -e

#
# Following variables should be defined to invoke this script
#
#   READELF
#   AWK
#

AWK_VERSION_OUTPUT=$($AWK 'BEGIN { print PROCINFO["version"] }')
if test -n "$AWK_VERSION_OUTPUT"; then
    # It's GNU awk, which supports PROCINFO.
    AWK_OPTION=--non-decimal-data
fi

FILE=.libs/libgcrypt.so

#
# Fixup the ELF header to clean up section information
#
printf '%b' '\002' > 2.bin
dd ibs=1 skip=4 count=1 if=$FILE status=none > class-byte.bin
if cmp class-byte.bin 2.bin; then
    CLASS=64
    HEADER_SIZE=64
else
    CLASS=32
    HEADER_SIZE=52
fi

if test $CLASS -eq 64; then
    dd ibs=1         count=40 if=$FILE     status=none
    dd ibs=1         count=8  if=/dev/zero status=none
    dd ibs=1 skip=48 count=10 if=$FILE     status=none
    dd ibs=1         count=6  if=/dev/zero status=none
else
    dd ibs=1         count=32 if=$FILE     status=none
    dd ibs=1         count=4  if=/dev/zero status=none
    dd ibs=1 skip=36 count=10 if=$FILE     status=none
    dd ibs=1         count=6  if=/dev/zero status=none
fi > header-fixed.bin

# Compute the end of loadable segment.
#
# This require computation in hexadecimal, and GNU awk needs
# --non-decimal-data option
#
OFFSET=$($READELF --wide --program-headers $FILE | \
         $AWK $AWK_OPTION "/^  LOAD/ { offset=\$2+\$5-$HEADER_SIZE }\
END { print offset}")

#
# Feed the header fixed and loadable segments to HMAC256
# to generate hmac hash of the FILE
#
(cat header-fixed.bin; \
 dd ibs=1 skip=$HEADER_SIZE count=$OFFSET if=$FILE status=none) \
 | ./hmac256 --stdkey --binary

rm -f 2.bin class-byte.bin header-fixed.bin
