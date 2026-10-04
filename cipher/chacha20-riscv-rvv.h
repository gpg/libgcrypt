/* chacha20-riscv-rvv.h - RISC-V vector implementation of ChaCha20
 * Copyright (C) 2025-2026 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
 */

#ifndef GCRY_CHACHA20_RISCV_RVV_H
#define GCRY_CHACHA20_RISCV_RVV_H

#include "simd-common-riscv.h"
#include <riscv_vector.h>
#include "bufhelp.h"


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


/**********************************************************************
  RISC-V vector extension chacha20
 **********************************************************************/

#define XOR(v, w)	__riscv_vxor_vv_u32m1((v), (w), vl)
#define PLUS(v, w)	__riscv_vadd_vv_u32m1((v), (w), vl)

#define QUARTERROUND_4(a0, b0, c0, d0, a1, b1, c1, d1, \
		       a2, b2, c2, d2, a3, b3, c3, d3) \
  a0 = PLUS(a0, b0); a1 = PLUS(a1, b1); \
  a2 = PLUS(a2, b2); a3 = PLUS(a3, b3); \
    d0 = XOR(d0, a0); d1 = XOR(d1, a1); \
    d2 = XOR(d2, a2); d3 = XOR(d3, a3); \
      d0 = ROTATE16(d0); d1 = ROTATE16(d1); \
      d2 = ROTATE16(d2); d3 = ROTATE16(d3); \
  c0 = PLUS(c0, d0); c1 = PLUS(c1, d1); \
  c2 = PLUS(c2, d2); c3 = PLUS(c3, d3); \
    b0 = XOR(b0, c0); b1 = XOR(b1, c1); \
    b2 = XOR(b2, c2); b3 = XOR(b3, c3); \
      b0 = ROTATE(b0, 12); b1 = ROTATE(b1, 12); \
      b2 = ROTATE(b2, 12); b3 = ROTATE(b3, 12); \
  a0 = PLUS(a0, b0); a1 = PLUS(a1, b1); \
  a2 = PLUS(a2, b2); a3 = PLUS(a3, b3); \
    d0 = XOR(d0, a0); d1 = XOR(d1, a1); \
    d2 = XOR(d2, a2); d3 = XOR(d3, a3); \
      d0 = ROTATE8(d0); d1 = ROTATE8(d1); \
      d2 = ROTATE8(d2); d3 = ROTATE8(d3); \
  c0 = PLUS(c0, d0); c1 = PLUS(c1, d1); \
  c2 = PLUS(c2, d2); c3 = PLUS(c3, d3); \
    b0 = XOR(b0, c0); b1 = XOR(b1, c1); \
    b2 = XOR(b2, c2); b3 = XOR(b3, c3); \
      b0 = ROTATE(b0, 7); b1 = ROTATE(b1, 7); \
      b2 = ROTATE(b2, 7); b3 = ROTATE(b3, 7);

#define vxor_v_u32m1_u32m1x4(data, idx, vs, vl) \
      __riscv_vset_v_u32m1_u32m1x4((data), (idx), \
	  __riscv_vxor_vv_u32m1( \
	      __riscv_vget_v_u32m1x4_u32m1((data), (idx)), (vs), (vl)))

#ifdef LOAD_GATHER_ROTATE_CONSTANTS

static ASM_FUNC_ATTR_INLINE vuint16m1_t
gen_rot16(size_t vl)
{
  return __riscv_vxor_vx_u16m1(__riscv_vid_v_u16m1(vl * 2), 1, vl * 2);
}

static ASM_FUNC_ATTR_INLINE vuint8m1_t
gen_rot8(size_t vl)
{
  vuint8m1_t rot8, rot8_hi;

  rot8 = __riscv_vid_v_u8m1(vl * 4);
  rot8_hi = __riscv_vand_vx_u8m1(rot8, ~3, vl * 4);
  rot8 = __riscv_vadd_vx_u8m1(rot8, 3, vl * 4);
  rot8 = __riscv_vand_vx_u8m1(rot8, 3, vl * 4);
  rot8 = __riscv_vadd_vv_u8m1(rot8, rot8_hi, vl * 4);

  return rot8;
}

#endif

static ASM_FUNC_ATTR_INLINE vuint16m2_t
gen_indexes(size_t vl, size_t stride)
{
  vuint16m2_t idx = __riscv_vid_v_u16m2(vl * 4);
  vuint16m2_t idx_lo = __riscv_vand_vx_u16m2(idx, 3, vl * 4);
  vuint16m2_t idx_hi = __riscv_vsrl_vx_u16m2(idx, 2, vl * 4);
  idx_hi = __riscv_vmul_vx_u16m2(idx_hi, stride, vl * 4);
  return __riscv_vadd_vv_u16m2(idx_hi, idx_lo, vl * 4);
}

static ASM_FUNC_ATTR_INLINE vuint32m1x4_t
unaligned_vlsseg4e32_v_u32m1x4(const void *src, size_t vl)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  if (UNLIKELY(((uintptr_t)src & 3) != 0))
    {
      const byte *bsrc = src;
      vuint16m2_t indexes;
      vuint8m1_t b0, b1, b2, b3;
      vuint32m1x4_t data;

      indexes = gen_indexes(4 * vl, 64);

      b0 = __riscv_vluxei16_v_u8m1(bsrc + 0 * 4, indexes, vl * 4);
      b1 = __riscv_vluxei16_v_u8m1(bsrc + 1 * 4, indexes, vl * 4);
      b2 = __riscv_vluxei16_v_u8m1(bsrc + 2 * 4, indexes, vl * 4);
      b3 = __riscv_vluxei16_v_u8m1(bsrc + 3 * 4, indexes, vl * 4);

      data = __riscv_vundefined_u32m1x4();
      data = __riscv_vset_v_u32m1_u32m1x4(
		data, 0, __riscv_vreinterpret_v_u8m1_u32m1(b0));
      data = __riscv_vset_v_u32m1_u32m1x4(
		data, 1, __riscv_vreinterpret_v_u8m1_u32m1(b1));
      data = __riscv_vset_v_u32m1_u32m1x4(
		data, 2, __riscv_vreinterpret_v_u8m1_u32m1(b2));
      data = __riscv_vset_v_u32m1_u32m1x4(
		data, 3, __riscv_vreinterpret_v_u8m1_u32m1(b3));

      return data;
    }
  else
#endif
    {
      /* Fast path for 32-bit aligned loads. */
      return __riscv_vlsseg4e32_v_u32m1x4(src, 64, vl);
    }
}

static ASM_FUNC_ATTR_INLINE void
unaligned_vssseg4e32_v_u32m1x4(void *dst, vuint32m1x4_t data, size_t vl)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  if (UNLIKELY(((uintptr_t)dst & 3) != 0))
    {
      byte *bdst = dst;
      vuint16m2_t indexes;
      vuint8m1_t b0, b1, b2, b3;

      indexes = gen_indexes(4 * vl, 64);

      b0 = __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vget_v_u32m1x4_u32m1(data, 0));
      b1 = __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vget_v_u32m1x4_u32m1(data, 1));
      b2 = __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vget_v_u32m1x4_u32m1(data, 2));
      b3 = __riscv_vreinterpret_v_u32m1_u8m1(__riscv_vget_v_u32m1x4_u32m1(data, 3));

      __riscv_vsuxei16_v_u8m1(bdst + 0 * 4, indexes, b0, vl * 4);
      __riscv_vsuxei16_v_u8m1(bdst + 1 * 4, indexes, b1, vl * 4);
      __riscv_vsuxei16_v_u8m1(bdst + 2 * 4, indexes, b2, vl * 4);
      __riscv_vsuxei16_v_u8m1(bdst + 3 * 4, indexes, b3, vl * 4);
    }
  else
#endif
    {
      /* Fast path for 32-bit aligned stores. */
      __riscv_vssseg4e32_v_u32m1x4(dst, 64, data, vl);
      return;
    }
}

/* Processes blocks while 4 or more remain. Returns number of blocks
 * processed, remaining 0 to 3 blocks are left for the caller. */
static ASM_FUNC_ATTR_INLINE size_t
chacha20_rvv_blocks(u32 *input, byte *dst, const byte *src, size_t nblks)
{
  size_t nblks_orig = nblks;
  unsigned int i;

  if (nblks >= 4)
    {
      size_t vl = __riscv_vsetvl_e32m1(nblks) < 4
		    ? __riscv_vsetvl_e32m1(4) : __riscv_vsetvl_e32m1(nblks);
      vuint32m1_t x0, x1, x2, x3, x4, x5, x6, x7;
      vuint32m1_t x8, x9, x10, x11, x12, x13, x14, x15;
      u32 s0, s1, s2, s3, s4, s5, s6, s7;
      u32 s8, s9, s10, s11, s12, s13, s14, s15;
#ifdef LOAD_GATHER_ROTATE_CONSTANTS
      vuint16m1_t rot16 = gen_rot16(vl);
      vuint8m1_t rot8 = gen_rot8(vl);
#endif

      s0 = input[0];
      s1 = input[1];
      s2 = input[2];
      s3 = input[3];
      s4 = input[4];
      s5 = input[5];
      s6 = input[6];
      s7 = input[7];
      s8 = input[8];
      s9 = input[9];
      s10 = input[10];
      s11 = input[11];
      s12 = input[12];
      s13 = input[13];
      s14 = input[14];
      s15 = input[15];

      while (nblks >= 4)
	{
	  vuint32m1_t ctr;
	  vbool32_t carry;
	  vuint32m1x4_t data;

	  if (vl < 4)
	    break;

	  x0 = __riscv_vmv_v_x_u32m1(s0, vl);
	  x1 = __riscv_vmv_v_x_u32m1(s1, vl);
	  x2 = __riscv_vmv_v_x_u32m1(s2, vl);
	  x3 = __riscv_vmv_v_x_u32m1(s3, vl);
	  x4 = __riscv_vmv_v_x_u32m1(s4, vl);
	  x5 = __riscv_vmv_v_x_u32m1(s5, vl);
	  x6 = __riscv_vmv_v_x_u32m1(s6, vl);
	  x7 = __riscv_vmv_v_x_u32m1(s7, vl);
	  x8 = __riscv_vmv_v_x_u32m1(s8, vl);
	  x9 = __riscv_vmv_v_x_u32m1(s9, vl);
	  x10 = __riscv_vmv_v_x_u32m1(s10, vl);
	  x11 = __riscv_vmv_v_x_u32m1(s11, vl);
	  x13 = __riscv_vmv_v_x_u32m1(s13, vl);
	  x14 = __riscv_vmv_v_x_u32m1(s14, vl);
	  x15 = __riscv_vmv_v_x_u32m1(s15, vl);

	  ctr = __riscv_vid_v_u32m1(vl);
	  carry = __riscv_vmadc_vx_u32m1_b32(ctr, s12, vl);
	  ctr = __riscv_vadd_vx_u32m1(ctr, s12, vl);
	  x12 = ctr;
	  x13 = __riscv_vadc_vxm_u32m1(x13, 0, carry, vl);

	  for (i = 20; i > 0; i -= 2)
	    {
	      QUARTERROUND_4(x0, x4,  x8, x12,
			     x1, x5,  x9, x13,
			     x2, x6, x10, x14,
			     x3, x7, x11, x15);
	      QUARTERROUND_4(x0, x5, x10, x15,
			     x1, x6, x11, x12,
		             x2, x7,  x8, x13,
		             x3, x4,  x9, x14);
	    }

	  x0 = __riscv_vadd_vx_u32m1(x0, s0, vl);
	  x1 = __riscv_vadd_vx_u32m1(x1, s1, vl);
	  x2 = __riscv_vadd_vx_u32m1(x2, s2, vl);
	  x3 = __riscv_vadd_vx_u32m1(x3, s3, vl);
	  x4 = __riscv_vadd_vx_u32m1(x4, s4, vl);
	  x5 = __riscv_vadd_vx_u32m1(x5, s5, vl);
	  x6 = __riscv_vadd_vx_u32m1(x6, s6, vl);
	  x7 = __riscv_vadd_vx_u32m1(x7, s7, vl);
	  x8 = __riscv_vadd_vx_u32m1(x8, s8, vl);
	  x9 = __riscv_vadd_vx_u32m1(x9, s9, vl);
	  x10 = __riscv_vadd_vx_u32m1(x10, s10, vl);
	  x11 = __riscv_vadd_vx_u32m1(x11, s11, vl);
	  x12 = __riscv_vadd_vv_u32m1(x12, ctr, vl);
	  x13 = __riscv_vadc_vxm_u32m1(x13, s13, carry, vl);
	  x14 = __riscv_vadd_vx_u32m1(x14, s14, vl);
	  x15 = __riscv_vadd_vx_u32m1(x15, s15, vl);

	  s12 += vl;
	  s13 += s12 < vl;

	  data = unaligned_vlsseg4e32_v_u32m1x4((const void *)src, vl);

	  data = vxor_v_u32m1_u32m1x4(data, 0, x0, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 1, x1, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 2, x2, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 3, x3, vl);

	  unaligned_vssseg4e32_v_u32m1x4((void *)dst, data, vl);

	  data = unaligned_vlsseg4e32_v_u32m1x4((const void *)(src + 16), vl);

	  data = vxor_v_u32m1_u32m1x4(data, 0, x4, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 1, x5, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 2, x6, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 3, x7, vl);

	  unaligned_vssseg4e32_v_u32m1x4((void *)(dst + 16), data, vl);

	  data = unaligned_vlsseg4e32_v_u32m1x4((const void *)(src + 32), vl);

	  data = vxor_v_u32m1_u32m1x4(data, 0, x8, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 1, x9, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 2, x10, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 3, x11, vl);

	  unaligned_vssseg4e32_v_u32m1x4((void *)(dst + 32), data, vl);

	  data = unaligned_vlsseg4e32_v_u32m1x4((const void *)(src + 48), vl);

	  data = vxor_v_u32m1_u32m1x4(data, 0, x12, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 1, x13, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 2, x14, vl);
	  data = vxor_v_u32m1_u32m1x4(data, 3, x15, vl);

	  unaligned_vssseg4e32_v_u32m1x4((void *)(dst + 48), data, vl);

	  src += vl * 64;
	  dst += vl * 64;
	  nblks -= vl;
	  vl = __riscv_vsetvl_e32m1(nblks) < 4
		    ? __riscv_vsetvl_e32m1(4) : __riscv_vsetvl_e32m1(nblks);
	}

      input[12] = s12;
      input[13] = s13;
    }

  clear_vec_regs();

  return nblks_orig - nblks;
}

#endif /* GCRY_CHACHA20_RISCV_RVV_H */
