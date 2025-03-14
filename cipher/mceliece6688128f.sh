#!/bin/sh

# mceliece6688128f.sh - Classic McEliece libmceliece->libgcrypt converter

# Based upon the public domain mceliece6688128f.sh from my merge
# request for Classic McEliece in OpenSSH, which in turn is based on
# the public domain OpenSSH sntrup761.sh script.

# Copyright (C) 2023-2024 Simon Josefsson <simon@josefsson.org>
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
# License along with this program; if not, see <https://www.gnu.org/licenses/>.
# SPDX-License-Identifier: LGPL-2.1-or-later

LICENSE="libmceliece-20230612/doc/license.md"
PEOPLE="libmceliece-20230612/doc/people.md"
FILES="	libmceliece-20230612/include-build/crypto_declassify.h
	libmceliece-20230612/crypto_kem/6688128f/vec/params.h
	libmceliece-20230612/inttypes/crypto_intN.h
	libmceliece-20230612/inttypes/crypto_intN.h
	libmceliece-20230612/inttypes/crypto_intN.h
	libmceliece-20230612/inttypes/crypto_uintN.h
	libmceliece-20230612/inttypes/crypto_uintN.h
	libmceliece-20230612/inttypes/crypto_uintN.h
	libmceliece-20230612/crypto_kem/6688128f/vec/vec.h
	libmceliece-20230612/crypto_kem/6688128f/vec/benes.h
	libmceliece-20230612/crypto_kem/6688128f/vec/bm.h
	libmceliece-20230612/crypto_kem/6688128f/vec/controlbits.h
	libmceliece-20230612/crypto_kem/6688128f/vec/decrypt.h
	libmceliece-20230612/crypto_kem/6688128f/vec/encrypt.h
	libmceliece-20230612/crypto_kem/6688128f/vec/fft_consts.h
	libmceliece-20230612/crypto_kem/6688128f/vec/fft.h
	libmceliece-20230612/crypto_kem/6688128f/vec/fft_powers.h
	libmceliece-20230612/crypto_kem/6688128f/vec/fft_scalars_2x.h
	libmceliece-20230612/crypto_kem/6688128f/vec/fft_scalars_4x.h
	libmceliece-20230612/crypto_kem/6688128f/vec/fft_tr.h
	libmceliece-20230612/crypto_kem/6688128f/vec/gf.h
	libmceliece-20230612/crypto_kem/6688128f/vec/hash.h
	libmceliece-20230612/crypto_kem/6688128f/vec/int32_sort.h
	libmceliece-20230612/crypto_kem/6688128f/vec/operations.h
	libmceliece-20230612/crypto_kem/6688128f/vec/pk_gen.h
	libmceliece-20230612/crypto_kem/6688128f/vec/sk_gen.h
	libmceliece-20230612/crypto_kem/6688128f/vec/transpose.h
	libmceliece-20230612/crypto_kem/6688128f/vec/uint16_sort.h
	libmceliece-20230612/crypto_kem/6688128f/vec/uint64_sort.h
	libmceliece-20230612/crypto_kem/6688128f/vec/util.h
	libmceliece-20230612/crypto_kem/6688128f/vec/benes.c
	libmceliece-20230612/crypto_kem/6688128f/vec/bm.c
	libmceliece-20230612/crypto_kem/6688128f/vec/controlbits.c
	libmceliece-20230612/crypto_kem/6688128f/vec/decrypt.c
	libmceliece-20230612/crypto_kem/6688128f/vec/encrypt.c
	libmceliece-20230612/crypto_kem/6688128f/vec/shared-fft_consts.c
	libmceliece-20230612/crypto_kem/6688128f/vec/shared-fft_powers.c
	libmceliece-20230612/crypto_kem/6688128f/vec/shared-fft_scalars_2x.c
	libmceliece-20230612/crypto_kem/6688128f/vec/shared-fft_scalars_4x.c
	libmceliece-20230612/crypto_kem/6688128f/vec/fft.c
	libmceliece-20230612/crypto_kem/6688128f/vec/fft_tr.c
	libmceliece-20230612/crypto_kem/6688128f/vec/gf.c
	libmceliece-20230612/crypto_kem/6688128f/vec/kem_dec.c
	libmceliece-20230612/crypto_kem/6688128f/vec/kem_enc.c
	libmceliece-20230612/crypto_kem/6688128f/vec/kem_keypair.c
	libmceliece-20230612/crypto_kem/6688128f/vec/pk_gen.c
	libmceliece-20230612/crypto_kem/6688128f/vec/sk_gen.c
	libmceliece-20230612/crypto_kem/6688128f/vec/vec.c
	libmceliece-20230612/crypto_kem/6688128f/vec/wrap_dec.c
	libmceliece-20230612/crypto_kem/6688128f/vec/wrap_enc.c
	libmceliece-20230612/crypto_kem/6688128f/vec/wrap_keypair.c"
###

set -e
cd $1
echo '/* mceliece6688128f.c - Classic McEliece for libgcrypt'
echo ' * Copyright (C) 2023-2024 Simon Josefsson <simon@josefsson.org>'
echo ' *'
echo ' * This file is part of Libgcrypt.'
echo ' *'
echo ' * Libgcrypt is free software; you can redistribute it and/or modify'
echo ' * it under the terms of the GNU Lesser General Public License as'
echo ' * published by the Free Software Foundation; either version 2.1 of'
echo ' * the License, or (at your option) any later version.'
echo ' *'
echo ' * Libgcrypt is distributed in the hope that it will be useful,'
echo ' * but WITHOUT ANY WARRANTY; without even the implied warranty of'
echo ' * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the'
echo ' * GNU Lesser General Public License for more details.'
echo ' *'
echo ' * You should have received a copy of the GNU Lesser General Public'
echo ' * License along with this program; if not, see <https://www.gnu.org/licenses/>.'
echo ' * SPDX-License-Identifier: LGPL-2.1-or-later'
echo ' *'
echo ' */'
echo ''
echo '/* This file is extracted from libmceliece. */'
echo
echo '/*'
sed -e 's/^/ * /' < $LICENSE | sed -e 's/ $//'
echo ' *'
sed -e 's/^/ * /' < $PEOPLE \
 | grep -v \
  -e 'The underlying `crypto_xof/shake256` software currently includes two' \
  -e 'SHAKE256 implementations. The `tweet` implementation is based on' \
  -e '\[https://twitter.com/tweetfips202\](https://twitter.com/tweetfips202)' \
  -e 'by Daniel J. Bernstein, Peter Schwabe, and Gilles Van Assche. The' \
  -e '`unrollround` implementation is from Daniel J. Bernstein.' \
 | sed -e 's/ $//'
echo ' * This file is generated by mceliece6688128f.sh from these files:'
echo ' *'
echo "$FILES" | sed -e 's/\t/ * /'
echo ' *'
echo ' */'
echo
echo '#ifdef HAVE_CONFIG_H'
echo '#include <config.h>'
echo '#endif'
echo
echo '#include "g10lib.h"'
echo '#include "mceliece6688128f.h"'
echo
cat<<EOF
static void
randombytes (uint8_t *out, size_t outlen)
{
  _gcry_randomize (out, outlen, GCRY_STRONG_RANDOM);
}

static void crypto_xof_shake256(unsigned char *h,long long hlen,
				const unsigned char *m,long long mlen)
{
  gcry_md_hd_t mdh;
  gcry_err_code_t ec;

  ec = _gcry_md_open (&mdh, GCRY_MD_SHAKE256, 0);
  if (ec)
    log_fatal ("internal md_open failed: %d\n", ec);
  _gcry_md_write (mdh, m, mlen);
  _gcry_md_extract (mdh, GCRY_MD_SHAKE256, h, hlen);
  _gcry_md_close (mdh);
}
EOF
N=16
for i in $FILES; do
	echo "/* from $i */"
	# Changes to all files:
	#  - remove all includes, we inline everything required.
	#  - make functions not required elsewhere static.
	#  - rename the functions we do use.
	#  - remove unnecessary defines and externs.
	sed -e "/#include/d" \
	    -e "s/{ ; }/{\n  (void) crypto_declassify_v;\n  (void) crypto_declassify_vlen;\n}/" \
	    -e "s/^void /static void /g" \
	    -e "s/^int /static int /g" \
	    -e "s/^int16 /static int16 /g" \
	    -e "s/^uint16 /static uint16 /g" \
	    -e "/^extern /d" \
	    -e "/perm_check/d" \
	    -e '/CRYPTO_NAMESPACE/d' \
	    -e '/CRYPTO_SHARED_NAMESPACE/d' \
	    -e 's/[	 ]*$//' \
	    $i | \
	case "$i" in
	# Use int64_t for intermediate values in int32_MINMAX to prevent signed
	# 32-bit integer overflow when called by crypto_sort_uint32.
	*/int32_sort.h)
	    sed -e "s/int32_t ab = b ^ a/int64_t ab = (int64_t)b ^ (int64_t)a/" \
	        -e "s/int32_t c = b - a/int64_t c = (int64_t)b - (int64_t)a/"
	    ;;
	# Silence false-alarm gcc warning about unitialized variable.
	*/kem_keypair.c)
	    sed -e "s/uint64_t pivots;/uint64_t pivots = 0;/"
	    ;;
	# This file clobbers namespace for one-letter variable names, and
	# overloads 'x' (of the same type!) within the same function.
	*/controlbits.c)
	    cat | sed \
		      -e "s,long long x = 2\*j;,long long lx = 2*j;," \
		      -e "s,int32 fj = B\[x\]\&1; /\* f\[j\] \*/,int32 fj = B[lx]\&1; /* f[j] */,g" \
		      -e "s,int32 Fx = x+fj; /\* F\[x\] \*/,int32 Fx = lx+fj; /* F[x] */,g" \
		      -e "s,B\[x\] = (A\[x\]<<16)|Fx;,B[lx] = (A[lx]<<16)|Fx;,g" \
		      -e "s,B\[x+1\] = (A\[x+1\]<<16)|Fx1;,B[lx+1] = (A[lx+1]<<16)|Fx1;,g"
	    echo '#undef A'
	    echo '#undef B'
	    echo '#undef q'
	    ;;
	# Poor-man's #include now that we removed all #include's above.
	*/shared-fft_*.c)
	    INC=$(echo $i | sed -e "s,/shared-fft_,/," -e "s,.c$,.data,")
	    DATA=$(echo $(cat $INC))
	    sed -e "s/};/$DATA\n};/"
	    ;;
	# Create three different versions of file depending on N.
	*/crypto_*intN.h)
	    sed -e "s/N/$N/g"
	    ;;
	# Default: pass through.
	*)
	    cat
	    ;;
	esac | \
        sed -e "s/__attribute__((unused))/GCC_ATTR_UNUSED/g" \
	    -e "s,^\([ \t]*\)//\(.*\)[ \t]*$,\1/*\2 */," \
	    -e "s,\([ \t]\+\)//\(.*\)[ \t]*$,\1/*\2 */,"
	echo
	if test "$N" = 16; then
	    N=32
	elif test "$N" = 32; then
	    N=64
	elif test "$N" = 64; then
	    N=16
	fi
done
cat<<EOF

/* libgcrypt wrapper */

void mceliece6688128f_dec(uint8_t *key,
			  const uint8_t *c,
			  const uint8_t *sk)
{
  crypto_kem_dec((unsigned char*) key,
		(unsigned char*) c,
		(unsigned char*) sk);
}

void mceliece6688128f_enc(uint8_t *c,
			  uint8_t *key,
			  const uint8_t *pk)
{
  crypto_kem_enc((unsigned char*) c,
		(unsigned char*) key,
		(unsigned char*) pk);
}

void mceliece6688128f_keypair(uint8_t *pk,
			      uint8_t *sk)
{
  crypto_kem_keypair((unsigned char*) pk, (unsigned char*) sk);
}
EOF
