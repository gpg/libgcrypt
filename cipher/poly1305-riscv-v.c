/* poly1305-riscv-v.c - RISC-V vector implementation of Poly1305
 *
 * Copyright (C) 2026 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
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
 * ---
 *
 * Core function `_gcry_poly1305_riscv_v_blocks` based on RISC-V vector
 * Poly1305 implementation `poly1305_blocks_vx` by Andy Polyakov from
 * CRYPTOGAMS distribution `riscv/poly1305-riscv.pl`. `poly1305_blocks_vx`
 * was converted to RVV intrinsics and fitted to libgcrypt Poly1305 state
 * and key power table. Key power precomputation was rewritten in C using
 * base 2^26 arithmetic.
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
 */

#include <config.h>

#include "poly1305-internal.h"

#ifdef POLY1305_USE_RISCV_V

#include "simd-common-riscv.h"
#include <riscv_vector.h>


#define ALWAYS_INLINE inline __attribute__((always_inline))
#define NO_INLINE __attribute__((noinline))
#define NO_INSTRUMENT_FUNCTION __attribute__((no_instrument_function))

#define ASM_FUNC_ATTR          NO_INSTRUMENT_FUNCTION
#define ASM_FUNC_ATTR_INLINE   ASM_FUNC_ATTR ALWAYS_INLINE
#define ASM_FUNC_ATTR_NOINLINE ASM_FUNC_ATTR NO_INLINE

#ifdef HAVE_GCC_ATTRIBUTE_OPTIMIZE
# define FUNC_ATTR_OPT_O2 __attribute__((optimize("-O2")))
#else
# define FUNC_ATTR_OPT_O2
#endif


/* Vector code uses up to 16 lanes (VLEN=1024, largest supported by QEMU),
 * needing key powers r^1 ... r^32. */
#define MAX_LANES 16

#define MASK26 ((1U << 26) - 1)


/**********************************************************************
  Key power precomputation
 **********************************************************************/

/* r = r^2 mod 2^130-5, base 2^26 */
static ASM_FUNC_ATTR_INLINE void
sqr_2_26 (u64 r[5])
{
  u64 r0 = r[0], r1 = r[1], r2 = r[2], r3 = r[3], r4 = r[4];
  u64 d0, d1, d2, d3, d4, c;

  d0 = r0 * r0 + 5 * 2 * (r1 * r4 + r2 * r3);
  d1 = 2 * r0 * r1 + 5 * (2 * r2 * r4 + r3 * r3);
  d2 = 2 * r0 * r2 + r1 * r1 + 5 * 2 * r3 * r4;
  d3 = 2 * (r0 * r3 + r1 * r2) + 5 * r4 * r4;
  d4 = 2 * (r0 * r4 + r1 * r3) + r2 * r2;

  c = d0 >> 26; d0 &= MASK26; d1 += c;
  c = d1 >> 26; d1 &= MASK26; d2 += c;
  c = d2 >> 26; d2 &= MASK26; d3 += c;
  c = d3 >> 26; d3 &= MASK26; d4 += c;
  c = d4 >> 26; d4 &= MASK26; d0 += c * 5;
  c = d0 >> 26; d0 &= MASK26; d1 += c;

  r[0] = d0;
  r[1] = d1;
  r[2] = d2;
  r[3] = d3;
  r[4] = d4;
}

/* Power table row for limb 'k' holds r^32, r^16, ..., r^2, r^1, so that
 * r^(2^i) is at index 5 - i and two neighboring powers can be loaded as
 * single pair. */
static ASM_FUNC_ATTR_NOINLINE size_t
compute_powers (poly1305_context_t *ctx, unsigned int npowers)
{
  u32 (*pwrs)[6] = ctx->riscv_v_powers;
  unsigned int i = ctx->riscv_v_npowers;
  u64 r[5];

  if (i == 0)
    {
      POLY1305_STATE *st = &ctx->state;
      u64 r0 = st->r[0] + ((u64)st->r[1] << 32);
      u64 r1 = st->r[2] + ((u64)st->r[3] << 32);

      r[0] = r0 & MASK26;
      r[1] = (r0 >> 26) & MASK26;
      r[2] = ((r0 >> 52) | (r1 << 12)) & MASK26;
      r[3] = (r1 >> 14) & MASK26;
      r[4] = r1 >> 40;
      i = 1;
      pwrs[0][5] = r[0];
      pwrs[1][5] = r[1];
      pwrs[2][5] = r[2];
      pwrs[3][5] = r[3];
      pwrs[4][5] = r[4];
    }
  else
    {
      r[0] = pwrs[0][6 - i];
      r[1] = pwrs[1][6 - i];
      r[2] = pwrs[2][6 - i];
      r[3] = pwrs[3][6 - i];
      r[4] = pwrs[4][6 - i];
    }

  for (; i < npowers; i++)
    {
      sqr_2_26 (r);
      pwrs[0][5 - i] = r[0];
      pwrs[1][5 - i] = r[1];
      pwrs[2][5 - i] = r[2];
      pwrs[3][5 - i] = r[3];
      pwrs[4][5 - i] = r[4];
    }

  ctx->riscv_v_npowers = npowers;

  return sizeof (r) + 128;
}


/**********************************************************************
  RISC-V vector extension Poly1305
 **********************************************************************/

/* Load 'vl' blocks, de-interleaved to four 32-bit words. */
static ASM_FUNC_ATTR_INLINE vuint32mf2x4_t
load_blocks (const byte *inp, u32 *alignbuf, size_t vl)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  if (UNLIKELY (((uintptr_t)inp & 3) != 0))
    {
      __riscv_vse8_v_u8m2((byte *)alignbuf,
			   __riscv_vle8_v_u8m2(inp, vl * 16), vl * 16);
      inp = (const byte *)alignbuf;
    }
#else
  (void)alignbuf;
#endif
  return __riscv_vlseg4e32_v_u32mf2x4((const void *)inp, vl);
}

/* Base 2^32 -> 2^26, with padbit. */
#define CONVERT_2_26(m, t) \
	m##0 = __riscv_vget_v_u32mf2x4_u32mf2(t, 0); \
	m##1 = __riscv_vget_v_u32mf2x4_u32mf2(t, 1); \
	m##2 = __riscv_vget_v_u32mf2x4_u32mf2(t, 2); \
	m##3 = __riscv_vget_v_u32mf2x4_u32mf2(t, 3); \
	m##4 = __riscv_vor_vx_u32mf2( \
		__riscv_vsrl_vx_u32mf2(m##3, 8, vl), 1 << 24, vl); \
	m##3 = __riscv_vand_vx_u32mf2( \
		__riscv_vor_vv_u32mf2( \
		  __riscv_vsll_vx_u32mf2(m##3, 18, vl), \
		  __riscv_vsrl_vx_u32mf2(m##2, 14, vl), vl), MASK26, vl); \
	m##2 = __riscv_vand_vx_u32mf2( \
		__riscv_vor_vv_u32mf2( \
		  __riscv_vsll_vx_u32mf2(m##2, 12, vl), \
		  __riscv_vsrl_vx_u32mf2(m##1, 20, vl), vl), MASK26, vl); \
	m##1 = __riscv_vand_vx_u32mf2( \
		__riscv_vor_vv_u32mf2( \
		  __riscv_vsll_vx_u32mf2(m##1, 6, vl), \
		  __riscv_vsrl_vx_u32mf2(m##0, 26, vl), vl), MASK26, vl); \
	m##0 = __riscv_vand_vx_u32mf2(m##0, MASK26, vl)

#define ADD_HASH(m, h) \
	m##0 = __riscv_vadd_vv_u32mf2(m##0, h##0, vl); \
	m##1 = __riscv_vadd_vv_u32mf2(m##1, h##1, vl); \
	m##2 = __riscv_vadd_vv_u32mf2(m##2, h##2, vl); \
	m##3 = __riscv_vadd_vv_u32mf2(m##3, h##3, vl); \
	m##4 = __riscv_vadd_vv_u32mf2(m##4, h##4, vl)

/*
 * d4 = h0*r4 + h1*r3   + h2*r2   + h3*r1   + h4*r0
 * d3 = h0*r3 + h1*r2   + h2*r1   + h3*r0   + h4*5*r4
 * d2 = h0*r2 + h1*r1   + h2*r0   + h3*5*r4 + h4*5*r3
 * d1 = h0*r1 + h1*r0   + h2*5*r4 + h3*5*r3 + h4*5*r2
 * d0 = h0*r0 + h1*5*r4 + h2*5*r3 + h3*5*r2 + h4*5*r1
 */
#define MAC_ROWS_1_4(d, h, r, op) \
	d##4 = op (d##4, r##3,   h##1, vl); \
	d##3 = op (d##3, r##2,   h##1, vl); \
	d##2 = op (d##2, r##1,   h##1, vl); \
	d##1 = op (d##1, r##0,   h##1, vl); \
	d##0 = op (d##0, r##4x5, h##1, vl); \
	\
	d##4 = op (d##4, r##2,   h##2, vl); \
	d##3 = op (d##3, r##1,   h##2, vl); \
	d##2 = op (d##2, r##0,   h##2, vl); \
	d##1 = op (d##1, r##4x5, h##2, vl); \
	d##0 = op (d##0, r##3x5, h##2, vl); \
	\
	d##4 = op (d##4, r##1,   h##3, vl); \
	d##3 = op (d##3, r##0,   h##3, vl); \
	d##2 = op (d##2, r##4x5, h##3, vl); \
	d##1 = op (d##1, r##3x5, h##3, vl); \
	d##0 = op (d##0, r##2x5, h##3, vl); \
	\
	d##4 = op (d##4, r##0,   h##4, vl); \
	d##3 = op (d##3, r##4x5, h##4, vl); \
	d##2 = op (d##2, r##3x5, h##4, vl); \
	d##1 = op (d##1, r##2x5, h##4, vl); \
	d##0 = op (d##0, r##1x5, h##4, vl)

/* d = h * r, with scalar r */
#define MUL_VX(d, h, r) \
	d##4 = __riscv_vwmulu_vx_u64m1(h##0, r##4, vl); \
	d##3 = __riscv_vwmulu_vx_u64m1(h##0, r##3, vl); \
	d##2 = __riscv_vwmulu_vx_u64m1(h##0, r##2, vl); \
	d##1 = __riscv_vwmulu_vx_u64m1(h##0, r##1, vl); \
	d##0 = __riscv_vwmulu_vx_u64m1(h##0, r##0, vl); \
	MAC_ROWS_1_4 (d, h, r, __riscv_vwmaccu_vx_u64m1)

/* d += h * r, with scalar r */
#define MAC_VX(d, h, r) \
	d##4 = __riscv_vwmaccu_vx_u64m1(d##4, r##4, h##0, vl); \
	d##3 = __riscv_vwmaccu_vx_u64m1(d##3, r##3, h##0, vl); \
	d##2 = __riscv_vwmaccu_vx_u64m1(d##2, r##2, h##0, vl); \
	d##1 = __riscv_vwmaccu_vx_u64m1(d##1, r##1, h##0, vl); \
	d##0 = __riscv_vwmaccu_vx_u64m1(d##0, r##0, h##0, vl); \
	MAC_ROWS_1_4 (d, h, r, __riscv_vwmaccu_vx_u64m1)

/* d = h * r, with vector r */
#define MUL_VV(d, h, r) \
	d##4 = __riscv_vwmulu_vv_u64m1(h##0, r##4, vl); \
	d##3 = __riscv_vwmulu_vv_u64m1(h##0, r##3, vl); \
	d##2 = __riscv_vwmulu_vv_u64m1(h##0, r##2, vl); \
	d##1 = __riscv_vwmulu_vv_u64m1(h##0, r##1, vl); \
	d##0 = __riscv_vwmulu_vv_u64m1(h##0, r##0, vl); \
	MAC_ROWS_1_4 (d, h, r, __riscv_vwmaccu_vv_u64m1)

/*
 * Lazy reduction as discussed in "NEON crypto" by D.J. Bernstein
 * and P. Schwabe
 *
 * H0>>+H1>>+H2>>+H3>>+H4
 * H3>>+H4>>*5+H0>>+H1
 *
 * >>+ denotes Hnext += Hn>>26, Hn &= 0x3ffffff.
 */
#define LAZY_REDC(h, d) do { \
	vuint64m1_t w0, w1, w2, w3, w4; \
	vuint32mf2_t c3; \
	\
	w3 = __riscv_vand_vx_u64m1(d##3, MASK26, vl); \
	d##3 = __riscv_vsrl_vx_u64m1(d##3, 26, vl); \
	w0 = __riscv_vand_vx_u64m1(d##0, MASK26, vl); \
	d##0 = __riscv_vsrl_vx_u64m1(d##0, 26, vl); \
	d##4 = __riscv_vadd_vv_u64m1(d##4, d##3, vl); \
	d##1 = __riscv_vadd_vv_u64m1(d##1, d##0, vl); \
	\
	w4 = __riscv_vand_vx_u64m1(d##4, MASK26, vl); \
	d##4 = __riscv_vsrl_vx_u64m1(d##4, 26, vl); \
	d##0 = __riscv_vsll_vx_u64m1(d##4, 2, vl); \
	w0 = __riscv_vadd_vv_u64m1(w0, d##4, vl); \
	w1 = __riscv_vand_vx_u64m1(d##1, MASK26, vl); \
	d##1 = __riscv_vsrl_vx_u64m1(d##1, 26, vl); \
	w0 = __riscv_vadd_vv_u64m1(w0, d##0, vl); \
	d##2 = __riscv_vadd_vv_u64m1(d##2, d##1, vl); \
	\
	d##0 = __riscv_vsrl_vx_u64m1(w0, 26, vl); \
	w0 = __riscv_vand_vx_u64m1(w0, MASK26, vl); \
	w2 = __riscv_vand_vx_u64m1(d##2, MASK26, vl); \
	d##2 = __riscv_vsrl_vx_u64m1(d##2, 26, vl); \
	w1 = __riscv_vadd_vv_u64m1(w1, d##0, vl); \
	w3 = __riscv_vadd_vv_u64m1(w3, d##2, vl); \
	\
	h##0 = __riscv_vncvt_x_x_w_u32mf2(w0, vl); \
	h##1 = __riscv_vncvt_x_x_w_u32mf2(w1, vl); \
	h##3 = __riscv_vncvt_x_x_w_u32mf2(w3, vl); \
	h##4 = __riscv_vncvt_x_x_w_u32mf2(w4, vl); \
	h##2 = __riscv_vncvt_x_x_w_u32mf2(w2, vl); \
	\
	c3 = __riscv_vsrl_vx_u32mf2(h##3, 26, vl); \
	h##3 = __riscv_vand_vx_u32mf2(h##3, MASK26, vl); \
	h##4 = __riscv_vadd_vv_u32mf2(h##4, c3, vl); \
      } while (0)

#define LOAD_SCALAR_POWER(r, idx) \
	r##0 = pwrs[0][idx]; \
	r##1 = pwrs[1][idx]; \
	r##2 = pwrs[2][idx]; \
	r##3 = pwrs[3][idx]; \
	r##4 = pwrs[4][idx]; \
	r##1x5 = r##1 * 5; \
	r##2x5 = r##2 * 5; \
	r##3x5 = r##3 * 5; \
	r##4x5 = r##4 * 5

/* Process input with 'nblks' blocks. Blocks are processed in multiples of
 * vector lane count and 'nblks' is updated to number of unprocessed
 * trailing blocks. Caller must provide at least 2 blocks. */
unsigned int ASM_FUNC_ATTR FUNC_ATTR_OPT_O2
_gcry_poly1305_riscv_v_blocks (poly1305_context_t *ctx, const byte *inp,
			       size_t *nblks)
{
  POLY1305_STATE *st = &ctx->state;
  u32 (*pwrs)[6] = ctx->riscv_v_powers;
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  u32 alignbuf[MAX_LANES * 4];
  size_t burn_stack = sizeof (alignbuf) + 32 * sizeof (u64);
#else
  u32 *alignbuf = NULL;
  size_t burn_stack = 32 * sizeof (u64);
#endif
  vuint32mf2_t h0, h1, h2, h3, h4;
  vuint32mf2_t lo0, lo1, lo2, lo3, lo4;
  vuint32mf2_t hi0, hi1, hi2, hi3, hi4;
  vuint64m1_t acc0, acc1, acc2, acc3, acc4;
  vuint32mf2x4_t data;
  u32 r4_0, r4_1, r4_2, r4_3, r4_4, r4_1x5, r4_2x5, r4_3x5, r4_4x5;
  u32 r8_0, r8_1, r8_2, r8_3, r8_4, r8_1x5, r8_2x5, r8_3x5, r8_4x5;
  u64 s0, s1, s2, s3, s4;
  u64 d0, d1, d2, t;
  size_t vl, n;
  unsigned int idx;

  vl = __riscv_vsetvlmax_e32mf2();
  if (vl > MAX_LANES)
    vl = MAX_LANES;

  /* Downsize lane count if input is too short. */
  while (vl > 2 && *nblks < 3 * vl)
    vl >>= 1;

  n = *nblks & ~(vl - 1);
  *nblks -= n;

  /* Index of r^vl in the power table. */
  for (idx = 5, t = vl; t > 1; t >>= 1)
    idx--;

  if (ctx->riscv_v_npowers < 7 - idx)
    burn_stack += compute_powers (ctx, 7 - idx);

  /* Convert hash value to base 2^26. */
  d0 = st->h[0] + ((u64)st->h[1] << 32);
  d1 = st->h[2] + ((u64)st->h[3] << 32);
  d2 = st->h[4];

  t = (d2 & ~(u64)3) + (d2 >> 2);
  d2 &= 3;

  s0 = d0 & MASK26;
  s1 = (d0 >> 26) & MASK26;
  s2 = ((d0 >> 52) | (d1 << 12)) & MASK26;
  s3 = (d1 >> 14) & MASK26;
  s4 = (d1 >> 40) | (d2 << 24);

  s0 += t & MASK26;
  t >>= 26;
  s1 += t & MASK26;
  t >>= 26;
  s2 += t;

  h0 = __riscv_vmv_s_x_u32mf2_tu(__riscv_vmv_v_x_u32mf2(0, vl), s0, vl);
  h1 = __riscv_vmv_s_x_u32mf2_tu(__riscv_vmv_v_x_u32mf2(0, vl), s1, vl);
  h2 = __riscv_vmv_s_x_u32mf2_tu(__riscv_vmv_v_x_u32mf2(0, vl), s2, vl);
  h3 = __riscv_vmv_s_x_u32mf2_tu(__riscv_vmv_v_x_u32mf2(0, vl), s3, vl);
  h4 = __riscv_vmv_s_x_u32mf2_tu(__riscv_vmv_v_x_u32mf2(0, vl), s4, vl);

  /* Two top-most powers, r^vl and r^(2*vl). */
  LOAD_SCALAR_POWER (r4_, idx);
  LOAD_SCALAR_POWER (r8_, idx - 1);

  /*
   * (((inp[0]*r^8 + inp[4]*r^4 + inp[8]) *r^4 + inp[12])*r^2 + )*r^2
   * (((inp[1]*r^8 + inp[5]*r^4 + inp[9]) *r^4 + inp[13])*r^2 + )*r^1
   * (((inp[2]*r^8 + inp[6]*r^4 + inp[10])*r^4 + inp[14]) ----^
   * (((inp[3]*r^8 + inp[7]*r^4 + inp[11])*r^4 + inp[15]) ----^
   *    \_____________________/
   * (((inp[0]*r^8 + inp[4]*r^4 + inp[8]) *r^8 + inp[12]*r^4 + inp[16])*r^2 + )*r^2
   * (((inp[1]*r^8 + inp[5]*r^4 + inp[9]) *r^8 + inp[13]*r^4 + inp[17])*r^2 + )*r
   * (((inp[2]*r^8 + inp[6]*r^4 + inp[10])*r^8 + inp[14]*r^4 + inp[18]) ----^
   * (((inp[3]*r^8 + inp[7]*r^4 + inp[11])*r^8 + inp[15]*r^4 + inp[19]) ----^
   *    \_____________________/ \__________________________/
   *
   * Note that we start with inp[vl:2*vl]*r^4. This is because it doesn't
   * depend on reduction in previous iteration.
   */

  data = load_blocks (inp, alignbuf, vl);
  inp += vl * 16;
  n -= vl;
  CONVERT_2_26 (lo, data);

  while (n >= 2 * vl)
    {
      data = load_blocks (inp, alignbuf, vl);
      inp += vl * 16;
      CONVERT_2_26 (hi, data);

      MUL_VX (acc, hi, r4_);

      /* (hash+inp[0:vl])*r^(2*vl) and accumulate */
      ADD_HASH (lo, h);
      MAC_VX (acc, lo, r8_);

      data = load_blocks (inp, alignbuf, vl);
      inp += vl * 16;
      CONVERT_2_26 (lo, data);

      LAZY_REDC (h, acc);

      n -= 2 * vl;
    }

  if (n)
    {
      ADD_HASH (lo, h);
      MUL_VX (acc, lo, r4_);

      data = load_blocks (inp, alignbuf, vl);
      CONVERT_2_26 (lo, data);

      LAZY_REDC (h, acc);
    }

  /* Reduce lanes by multiplying upper half with r^(vl/2) and adding
   * to lower half. */
  ADD_HASH (lo, h);
  while (vl > 2)
    {
      idx++;
      LOAD_SCALAR_POWER (r4_, idx);
      MUL_VX (acc, lo, r4_);

      LAZY_REDC (h, acc);

      vl >>= 1;
      lo0 = __riscv_vslidedown_vx_u32mf2(lo0, vl, vl);
      lo1 = __riscv_vslidedown_vx_u32mf2(lo1, vl, vl);
      lo2 = __riscv_vslidedown_vx_u32mf2(lo2, vl, vl);
      lo3 = __riscv_vslidedown_vx_u32mf2(lo3, vl, vl);
      lo4 = __riscv_vslidedown_vx_u32mf2(lo4, vl, vl);
      ADD_HASH (lo, h);
    }

  /* Last two lanes, multiply with r^2 and r^1. */
  hi0 = __riscv_vle32_v_u32mf2(&pwrs[0][4], vl);
  hi1 = __riscv_vle32_v_u32mf2(&pwrs[1][4], vl);
  hi2 = __riscv_vle32_v_u32mf2(&pwrs[2][4], vl);
  hi3 = __riscv_vle32_v_u32mf2(&pwrs[3][4], vl);
  hi4 = __riscv_vle32_v_u32mf2(&pwrs[4][4], vl);
  {
    vuint32mf2_t hi1x5 = __riscv_vmul_vx_u32mf2(hi1, 5, vl);
    vuint32mf2_t hi2x5 = __riscv_vmul_vx_u32mf2(hi2, 5, vl);
    vuint32mf2_t hi3x5 = __riscv_vmul_vx_u32mf2(hi3, 5, vl);
    vuint32mf2_t hi4x5 = __riscv_vmul_vx_u32mf2(hi4, 5, vl);

    MUL_VV (acc, lo, hi);
  }

  LAZY_REDC (h, acc);

  h0 = __riscv_vadd_vv_u32mf2(h0, __riscv_vslidedown_vx_u32mf2(h0, 1, 1), 1);
  h1 = __riscv_vadd_vv_u32mf2(h1, __riscv_vslidedown_vx_u32mf2(h1, 1, 1), 1);
  h2 = __riscv_vadd_vv_u32mf2(h2, __riscv_vslidedown_vx_u32mf2(h2, 1, 1), 1);
  h3 = __riscv_vadd_vv_u32mf2(h3, __riscv_vslidedown_vx_u32mf2(h3, 1, 1), 1);
  h4 = __riscv_vadd_vv_u32mf2(h4, __riscv_vslidedown_vx_u32mf2(h4, 1, 1), 1);

  s0 = __riscv_vmv_x_s_u32mf2_u32(h0);
  s1 = __riscv_vmv_x_s_u32mf2_u32(h1);
  s2 = __riscv_vmv_x_s_u32mf2_u32(h2);
  s3 = __riscv_vmv_x_s_u32mf2_u32(h3);
  s4 = __riscv_vmv_x_s_u32mf2_u32(h4);

  /* Convert hash value to base 2^64. */
  d0 = s0 + (s1 << 26);
  t = s2 << 52;
  d0 += t;
  d1 = (s2 >> 12) + (d0 < t);
  d1 += s3 << 14;
  t = s4 << 40;
  d1 += t;
  d2 = (s4 >> 24) + (d1 < t);

  /* Lane sum can exceed 2^131-5, fold bits above 2^130 for poly1305_final. */
  t = (d2 & ~(u64)3) + (d2 >> 2);
  d2 &= 3;
  d0 += t;
  t = d0 < t;
  d1 += t;
  d2 += d1 < t;

  st->h[0] = d0;
  st->h[1] = d0 >> 32;
  st->h[2] = d1;
  st->h[3] = d1 >> 32;
  st->h[4] = d2;

  clear_vec_regs ();

  return burn_stack;
}

unsigned int ASM_FUNC_ATTR FUNC_ATTR_OPT_O2
_gcry_poly1305_riscv_v_check_hw (void)
{
  return (__riscv_vsetvl_e8m1(16) == 16);
}

#endif /* POLY1305_USE_RISCV_V */
