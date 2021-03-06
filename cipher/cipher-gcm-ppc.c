/* cipher-gcm-ppc.c  -  Power 8 vpmsum accelerated Galois Counter Mode
 *                      implementation
 * Copyright (C) 2019 Shawn Landden <shawn@git.icu>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * Libgcrypt is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Based on GHASH implementation by Andy Polyakov from CRYPTOGAMS
 * distribution (ppc/ghashp8-ppc.pl). Specifically, it uses his register
 * allocation (which then defers to your compiler's register allocation),
 * instead of re-implementing Gerald Estrin's Scheme of parallelized
 * multiplication of polynomials, as I did not understand this algorithm at
 * the time.
 *
 * Original copyright license follows:
 *
 *  Copyright (c) 2006, CRYPTOGAMS by <appro@openssl.org>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *        * Redistributions of source code must retain copyright notices,
 *          this list of conditions and the following disclaimer.
 *
 *        * Redistributions in binary form must reproduce the above
 *          copyright notice, this list of conditions and the following
 *          disclaimer in the documentation and/or other materials
 *          provided with the distribution.
 *
 *        * Neither the name of the CRYPTOGAMS nor the names of its
 *          copyright holder and contributors may be used to endorse or
 *          promote products derived from this software without specific
 *          prior written permission.
 *
 *  ALTERNATIVELY, provided that this notice is retained in full, this
 *  product may be distributed under the terms of the GNU General Public
 *  License (GPL), in which case the provisions of the GPL apply INSTEAD OF
 *  those given above.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 *  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0-only)
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "./cipher-internal.h"

#ifdef GCM_USE_PPC_VPMSUM

#include <altivec.h>

#define ALWAYS_INLINE inline __attribute__((always_inline))
#define NO_INSTRUMENT_FUNCTION __attribute__((no_instrument_function))

#define ASM_FUNC_ATTR        NO_INSTRUMENT_FUNCTION
#define ASM_FUNC_ATTR_INLINE ASM_FUNC_ATTR ALWAYS_INLINE

typedef vector unsigned char vector16x_u8;
typedef vector signed char vector16x_s8;
typedef vector unsigned long long vector2x_u64;
typedef vector unsigned long long block;

static ASM_FUNC_ATTR_INLINE block
asm_vpmsumd(block a, block b)
{
  block r;
  __asm__("vpmsumd %0, %1, %2"
	  : "=v" (r)
	  : "v" (a), "v" (b));
  return r;
}

static ASM_FUNC_ATTR_INLINE block
asm_swap_u64(block a)
{
  __asm__("xxswapd %x0, %x1"
          : "=wa" (a)
          : "wa" (a));
  return a;
}

static ASM_FUNC_ATTR_INLINE block
asm_rot_block_left(block a)
{
  block zero = {0, 0};
  block mask = {2, 0};
  return __builtin_shuffle(a, zero, mask);
}

static ASM_FUNC_ATTR_INLINE block
asm_rot_block_right(block a)
{
  block zero = {0, 0};
  block mask = {1, 2};
  return __builtin_shuffle(a, zero, mask);
}

/* vsl is a slightly strange function in the way the shift is passed... */
static ASM_FUNC_ATTR_INLINE block
asm_ashl_128(block a, vector16x_u8 shift)
{
  block r;
  __asm__("vsl %0, %1, %2"
          : "=v" (r)
          : "v" (a), "v" (shift));
  return r;
}

#define ALIGNED_LOAD(in_ptr) \
  (vec_aligned_ld (0, (const unsigned char *)(in_ptr)))

static ASM_FUNC_ATTR_INLINE block
vec_aligned_ld(unsigned long offset, const unsigned char *ptr)
{
#ifndef WORDS_BIGENDIAN
  block vec;
  __asm__ ("lvx %0,%1,%2\n\t"
	   : "=v" (vec)
	   : "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory", "r0");
  return vec;
#else
  return vec_vsx_ld (offset, ptr);
#endif
}

#define STORE_TABLE(gcm_table, slot, vec) \
  vec_aligned_st (((block)vec), slot * 16, (unsigned char *)(gcm_table));


static ASM_FUNC_ATTR_INLINE void
vec_aligned_st(block vec, unsigned long offset, unsigned char *ptr)
{
#ifndef WORDS_BIGENDIAN
  __asm__ ("stvx %0,%1,%2\n\t"
	   :
	   : "v" (vec), "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory", "r0");
#else
  vec_vsx_st ((vector16x_u8)vec, offset, ptr);
#endif
}

#define VEC_LOAD_BE(in_ptr, bswap_const) \
  (vec_load_be (0, (const unsigned char *)(in_ptr), bswap_const))

static ASM_FUNC_ATTR_INLINE block
vec_load_be(unsigned long offset, const unsigned char *ptr,
	    vector unsigned char be_bswap_const)
{
#ifndef WORDS_BIGENDIAN
  block vec;
  /* GCC vec_vsx_ld is generating two instructions on little-endian. Use
   * lxvw4x directly instead. */
  __asm__ ("lxvw4x %x0,%1,%2\n\t"
	   : "=wa" (vec)
	   : "r" (offset), "r" ((uintptr_t)ptr)
	   : "memory", "r0");
  __asm__ ("vperm %0,%1,%1,%2\n\t"
	   : "=v" (vec)
	   : "v" (vec), "v" (be_bswap_const));
  return vec;
#else
  (void)be_bswap_const;
  return vec_vsx_ld (offset, ptr);
#endif
}

/* Power ghash based on papers:
   "The Galois/Counter Mode of Operation (GCM)"; David A. McGrew, John Viega
   "Intel® Carry-Less Multiplication Instruction and its Usage for Computing
    the GCM Mode - Rev 2.01"; Shay Gueron, Michael E. Kounavis.

   After saving the magic c2 constant and pre-formatted version of the key,
   we pre-process the key for parallel hashing. This takes advantage of the
   identity of addition over a galois field being identital to XOR, and thus
   can be parellized (S 2.2, page 3). We multiply and add (galois field
   versions) the key over multiple iterations and save the result. This can
   later be galois added (XORed) with parallel processed input (Estrin's
   Scheme).

   The ghash "key" is a salt. */
void ASM_FUNC_ATTR
_gcry_ghash_setup_ppc_vpmsum (uint64_t *gcm_table, void *gcm_key)
{
  vector16x_u8 bswap_const =
    { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
  vector16x_u8 c2 =
    { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0b11000010 };
  block T0, T1, T2;
  block C2, H, H1, H1l, H1h, H2, H2l, H2h;
  block H3l, H3, H3h, H4l, H4, H4h, T3, T4;
  vector16x_s8 most_sig_of_H, t7, carry;
  vector16x_u8 one = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

  H = VEC_LOAD_BE(gcm_key, bswap_const);
  most_sig_of_H = vec_splat((vector16x_s8)H, 15);
  t7 = vec_splat_s8(7);
  carry = most_sig_of_H >> t7;
  carry &= c2; /* only interested in certain carries. */
  H1 = asm_ashl_128(H, one);
  H1 ^= (block)carry; /* complete the <<< 1 */

  T1 = asm_swap_u64 (H1);
  H1l = asm_rot_block_right (T1);
  H1h = asm_rot_block_left (T1);
  C2 = asm_rot_block_right ((block)c2);

  STORE_TABLE (gcm_table, 0, C2);
  STORE_TABLE (gcm_table, 1, H1l);
  STORE_TABLE (gcm_table, 2, T1);
  STORE_TABLE (gcm_table, 3, H1h);

  /* pre-process coefficients for Gerald Estrin's scheme for parallel
   * multiplication of polynomials
   */
  H2l = asm_vpmsumd (H1l, H1); /* do not need to mask in
                                  because 0 * anything -> 0 */
  H2 = asm_vpmsumd (T1, H1);
  H2h = asm_vpmsumd (H1h, H1);

  /* reduce 1 */
  T0 = asm_vpmsumd (H2l, C2);

  H2l ^= asm_rot_block_left (H2);;
  H2h ^= asm_rot_block_right (H2);
  H2l = asm_swap_u64 (H2l);
  H2l ^= T0;
  /* reduce 2 */
  T0 = asm_swap_u64 (H2l);
  H2l = asm_vpmsumd (H2l, C2);
  H2 = H2l ^ H2h ^ T0;

  T2 = asm_swap_u64 (H2);
  H2l = asm_rot_block_right (T2);
  H2h = asm_rot_block_left (T2);

  STORE_TABLE (gcm_table, 4, H2l);
  STORE_TABLE (gcm_table, 5, T2);
  STORE_TABLE (gcm_table, 6, H2h);

  H3l = asm_vpmsumd (H2l, H1);
  H4l = asm_vpmsumd (H2l, H2);
  H3 = asm_vpmsumd (T2, H1);
  H4 = asm_vpmsumd (T2, H2);
  H3h = asm_vpmsumd (H2h, H1);
  H4h = asm_vpmsumd (H2h, H2);

  T3 = asm_vpmsumd (H3l, C2);
  T4 = asm_vpmsumd (H4l, C2);

  H3l ^= asm_rot_block_left (H3);
  H3h ^= asm_rot_block_right (H3);
  H4l ^= asm_rot_block_left (H4);
  H4h ^= asm_rot_block_right (H4);

  H3 = asm_swap_u64 (H3l);
  H4 = asm_swap_u64 (H4l);

  H3 ^= T3;
  H4 ^= T4;

  /* We could have also b64 switched reduce and reduce2, however as we are
     using the unrotated H and H2 above to vpmsum, this is marginally better. */
  T3 = asm_swap_u64 (H3);
  T4 = asm_swap_u64 (H4);

  H3 = asm_vpmsumd (H3, C2);
  H4 = asm_vpmsumd (H4, C2);

  T3 ^= H3h;
  T4 ^= H4h;
  H3 ^= T3;
  H4 ^= T4;
  H3 = asm_swap_u64 (H3);
  H4 = asm_swap_u64 (H4);

  H3l = asm_rot_block_right (H3);
  H3h = asm_rot_block_left (H3);
  H4l = asm_rot_block_right (H4);
  H4h = asm_rot_block_left (H4);

  STORE_TABLE (gcm_table, 7, H3l);
  STORE_TABLE (gcm_table, 8, H3);
  STORE_TABLE (gcm_table, 9, H3h);
  STORE_TABLE (gcm_table, 10, H4l);
  STORE_TABLE (gcm_table, 11, H4);
  STORE_TABLE (gcm_table, 12, H4h);
}

ASM_FUNC_ATTR_INLINE
block
vec_perm2(block l, block r, vector16x_u8 perm) {
  block ret;
  __asm__ ("vperm %0,%1,%2,%3\n\t"
	   : "=v" (ret)
	   : "v" (l), "v" (r), "v" (perm));
  return ret;
}

void ASM_FUNC_ATTR
_gcry_ghash_ppc_vpmsum (const byte *result, const void *const gcm_table,
			const byte *const buf, const size_t nblocks)
{
  /* This const is strange, it is reversing the bytes, and also reversing
     the u32s that get switched by lxvw4 and it also addresses bytes big-endian,
     and is here due to lack of proper peep-hole optimization. */
  vector16x_u8 bswap_const =
    { 12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3 };
  vector16x_u8 bswap_8_const =
    { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  block c2, H0l, H0m, H0h, H4l, H4m, H4h, H2m, H3l, H3m, H3h, Hl;
  block Hm, Hh, in, in0, in1, in2, in3, Hm_right, Hl_rotate, cur;
  size_t blocks_remaining = nblocks, off = 0;
  size_t not_multiple_of_four;
  block t0;

  cur = vec_load_be (0, result, bswap_const);

  c2 = vec_aligned_ld (0, gcm_table);
  H0l = vec_aligned_ld (16, gcm_table);
  H0m = vec_aligned_ld (32, gcm_table);
  H0h = vec_aligned_ld (48, gcm_table);

  for (not_multiple_of_four = nblocks % 4; not_multiple_of_four;
       not_multiple_of_four--)
    {
      in = vec_load_be (off, buf, bswap_const);
      off += 16;
      blocks_remaining--;
      cur ^= in;

      Hl = asm_vpmsumd (cur, H0l);
      Hm = asm_vpmsumd (cur, H0m);
      Hh = asm_vpmsumd (cur, H0h);

      t0 = asm_vpmsumd (Hl, c2);

      Hl ^= asm_rot_block_left (Hm);

      Hm_right = asm_rot_block_right (Hm);
      Hh ^= Hm_right;
      Hl_rotate = asm_swap_u64 (Hl);
      Hl_rotate ^= t0;
      Hl = asm_swap_u64 (Hl_rotate);
      Hl_rotate = asm_vpmsumd (Hl_rotate, c2);
      Hl ^= Hh;
      Hl ^= Hl_rotate;

      cur = Hl;
  }

  if (blocks_remaining > 0)
    {
      vector16x_u8 hiperm =
	{
	  0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
	  0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0
	};
      vector16x_u8 loperm =
        {
	  0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18,
	  0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8
	};
      block Xl, Xm, Xh, Xl1, Xm1, Xh1, Xm2, Xl3, Xm3, Xh3, Xl_rotate;
      block H21l, H21h, merge_l, merge_h;

      H2m = vec_aligned_ld (48 + 32, gcm_table);
      H3l = vec_aligned_ld (48 * 2 + 16, gcm_table);
      H3m = vec_aligned_ld (48 * 2 + 32, gcm_table);
      H3h = vec_aligned_ld (48 * 2 + 48, gcm_table);
      H4l = vec_aligned_ld (48 * 3 + 16, gcm_table);
      H4m = vec_aligned_ld (48 * 3 + 32, gcm_table);
      H4h = vec_aligned_ld (48 * 3 + 48, gcm_table);

      in0 = vec_load_be (off, buf, bswap_const);
      in1 = vec_load_be (off + 16, buf, bswap_const);
      in2 = vec_load_be (off + 32, buf, bswap_const);
      in3 = vec_load_be (off + 48, buf, bswap_const);
      blocks_remaining -= 4;
      off += 64;

      Xh = in0 ^ cur;

      Xl1 = asm_vpmsumd (in1, H3l);
      Xm1 = asm_vpmsumd (in1, H3m);
      Xh1 = asm_vpmsumd (in1, H3h);

      H21l = vec_perm2 (H2m, H0m, hiperm);
      H21h = vec_perm2 (H2m, H0m, loperm);
      merge_l = vec_perm2 (in2, in3, loperm);
      merge_h = vec_perm2 (in2, in3, hiperm);

      Xm2 = asm_vpmsumd (in2, H2m);
      Xl3 = asm_vpmsumd (merge_l, H21l);
      Xm3 = asm_vpmsumd (in3, H0m);
      Xh3 = asm_vpmsumd (merge_h, H21h);

      Xm2 ^= Xm1;
      Xl3 ^= Xl1;
      Xm3 ^= Xm2;
      Xh3 ^= Xh1;

      /* Gerald Estrin's scheme for parallel multiplication of polynomials */
      for (;blocks_remaining > 0; blocks_remaining -= 4, off += 64)
        {
	  in0 = vec_load_be (off, buf, bswap_const);
	  in1 = vec_load_be (off + 16, buf, bswap_const);
	  in2 = vec_load_be (off + 32, buf, bswap_const);
	  in3 = vec_load_be (off + 48, buf, bswap_const);

	  Xl = asm_vpmsumd (Xh, H4l);
	  Xm = asm_vpmsumd (Xh, H4m);
	  Xh = asm_vpmsumd (Xh, H4h);
	  Xl1 = asm_vpmsumd (in1, H3l);
	  Xm1 = asm_vpmsumd (in1, H3m);
	  Xh1 = asm_vpmsumd (in1, H3h);

	  Xl ^= Xl3;
	  Xm ^= Xm3;
	  Xh ^= Xh3;
	  merge_l = vec_perm2 (in2, in3, loperm);
	  merge_h = vec_perm2 (in2, in3, hiperm);

	  t0 = asm_vpmsumd (Xl, c2);
	  Xl3 = asm_vpmsumd (merge_l, H21l);
	  Xh3 = asm_vpmsumd (merge_h, H21h);

	  Xl ^= asm_rot_block_left (Xm);
	  Xh ^= asm_rot_block_right (Xm);

	  Xl = asm_swap_u64 (Xl);
	  Xl ^= t0;

	  Xl_rotate = asm_swap_u64 (Xl);
	  Xm2 = asm_vpmsumd (in2, H2m);
	  Xm3 = asm_vpmsumd (in3, H0m);
	  Xl = asm_vpmsumd (Xl, c2);

	  Xl3 ^= Xl1;
	  Xh3 ^= Xh1;
	  Xh ^= in0;
	  Xm2 ^= Xm1;
	  Xh ^= Xl_rotate;
	  Xm3 ^= Xm2;
	  Xh ^= Xl;
	}

      Xl = asm_vpmsumd (Xh, H4l);
      Xm = asm_vpmsumd (Xh, H4m);
      Xh = asm_vpmsumd (Xh, H4h);

      Xl ^= Xl3;
      Xm ^= Xm3;

      t0 = asm_vpmsumd (Xl, c2);

      Xh ^= Xh3;
      Xl ^= asm_rot_block_left (Xm);
      Xh ^= asm_rot_block_right (Xm);

      Xl = asm_swap_u64 (Xl);
      Xl ^= t0;

      Xl_rotate = asm_swap_u64 (Xl);
      Xl = asm_vpmsumd (Xl, c2);
      Xl_rotate ^= Xh;
      Xl ^= Xl_rotate;

      cur = Xl;
    }

  cur = (block)vec_perm ((vector16x_u8)cur, (vector16x_u8)cur, bswap_8_const);
  STORE_TABLE (result, 0, cur);
}

#endif /* GCM_USE_PPC_VPMSUM */
