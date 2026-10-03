/* sm4-riscv-zvksed-zvkb.c - RISC-V vector crypto implementation of SM4
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
 */

#include <config.h>

#if defined (__riscv) && \
    defined(HAVE_COMPATIBLE_CC_RISCV_VECTOR_INTRINSICS) && \
    defined(HAVE_COMPATIBLE_CC_RISCV_VECTOR_CRYPTO_INTRINSICS) && \
    defined(USE_SM4)

#include "g10lib.h"
#include "bufhelp.h"
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


#define SM4_ROUND_KEY_VARIABLES \
  vuint32m1_t rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7

#define SM4_ROUND_KEY_PARAMS \
  vuint32m1_t rk0, vuint32m1_t rk1, vuint32m1_t rk2, vuint32m1_t rk3, \
  vuint32m1_t rk4, vuint32m1_t rk5, vuint32m1_t rk6, vuint32m1_t rk7

#define SM4_ROUND_KEYS rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7

#define SM4_LOAD_ROUND_KEYS(rk) \
  rk0 = __riscv_vle32_v_u32m1(rk + 0 * 4, 4); \
  rk1 = __riscv_vle32_v_u32m1(rk + 1 * 4, 4); \
  rk2 = __riscv_vle32_v_u32m1(rk + 2 * 4, 4); \
  rk3 = __riscv_vle32_v_u32m1(rk + 3 * 4, 4); \
  rk4 = __riscv_vle32_v_u32m1(rk + 4 * 4, 4); \
  rk5 = __riscv_vle32_v_u32m1(rk + 5 * 4, 4); \
  rk6 = __riscv_vle32_v_u32m1(rk + 6 * 4, 4); \
  rk7 = __riscv_vle32_v_u32m1(rk + 7 * 4, 4)

#define SM4_NEXT_BLOCKS(n) \
  in += (n) * 16; \
  out += (n) * 16; \
  nblocks -= (n)

#define SM4_LMUL m1
#define SM4_MASK64_T vbool64_t
#include "sm4-riscv-zvksed-zvkb.h"

#define SM4_LMUL m2
#define SM4_MASK64_T vbool32_t
#include "sm4-riscv-zvksed-zvkb.h"

#define SM4_LMUL m4
#define SM4_MASK64_T vbool16_t
#include "sm4-riscv-zvksed-zvkb.h"


unsigned int ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_sm4_riscv_zvksed_crypt (const u32 *rk, byte *out, const byte *in,
			      size_t nblocks)
{
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  SM4_ROUND_KEY_VARIABLES;

  SM4_LOAD_ROUND_KEYS(rk);

  if (nblocks > max_blocks_m2)
    {
      vbool16_t even_m4 = even_mask_m4();

      while (nblocks >= max_blocks_m4)
	{
	  sm4_ecb_blocks_m4(SM4_ROUND_KEYS, even_m4, out, in, max_blocks_m4);
	  SM4_NEXT_BLOCKS(max_blocks_m4);
	}
      if (nblocks > max_blocks_m2)
	{
	  sm4_ecb_blocks_m4(SM4_ROUND_KEYS, even_m4, out, in, nblocks);
	  SM4_NEXT_BLOCKS(nblocks);
	}
    }
  if (nblocks > max_blocks_m1)
    sm4_ecb_blocks_m2(SM4_ROUND_KEYS, even_mask_m2(), out, in, nblocks);
  else if (nblocks)
    sm4_ecb_blocks_m1(SM4_ROUND_KEYS, even_mask_m1(), out, in, nblocks);

  clear_vec_regs();

  return 0;
}


/* Caller handles carry beyond low 16 bits of counter.  */
void ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_sm4_riscv_zvksed_ctr_enc (const u32 *rk, byte *out, const byte *in,
				byte *ctr, size_t nblocks)
{
  u64 ctr_lo = rol64(buf_get_be64(ctr + 0), 32);
  u64 ctr_hi_noswap = buf_get_be64(ctr + 8);
  u64 ctr_hi = rol64(ctr_hi_noswap, 32);
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  SM4_ROUND_KEY_VARIABLES;

  SM4_LOAD_ROUND_KEYS(rk);

  ctr[14] = (ctr_hi_noswap + nblocks) >> 8;
  ctr[15] = (ctr_hi_noswap + nblocks) >> 0;

  if (nblocks > max_blocks_m2)
    {
      vbool16_t even_m4 = even_mask_m4();
      vuint64m4_t ctr_m4 = ctr_init_m4(even_m4, ctr_lo, ctr_hi);
      vuint64m4_t inc_m4 = ctr_inc_m4(even_m4, max_blocks_m4);

      while (nblocks >= max_blocks_m4)
	{
	  sm4_ctr_blocks_m4(SM4_ROUND_KEYS, even_m4, &ctr_m4, inc_m4, out, in,
			    max_blocks_m4);
	  ctr_hi += (u64)max_blocks_m4 << 32;
	  SM4_NEXT_BLOCKS(max_blocks_m4);
	}
      if (nblocks > max_blocks_m2)
	{
	  sm4_ctr_blocks_m4(SM4_ROUND_KEYS, even_m4, &ctr_m4, inc_m4, out, in,
			    nblocks);
	  ctr_hi += (u64)nblocks << 32;
	  SM4_NEXT_BLOCKS(nblocks);
	}
    }
  if (nblocks > max_blocks_m1)
    {
      vbool32_t even_m2 = even_mask_m2();
      vuint64m2_t ctr_m2 = ctr_init_m2(even_m2, ctr_lo, ctr_hi);

      sm4_ctr_blocks_m2(SM4_ROUND_KEYS, even_m2, &ctr_m2,
			ctr_inc_m2(even_m2, max_blocks_m2), out, in, nblocks);
    }
  else if (nblocks)
    {
      vbool64_t even_m1 = even_mask_m1();
      vuint64m1_t ctr_m1 = ctr_init_m1(even_m1, ctr_lo, ctr_hi);

      sm4_ctr_blocks_m1(SM4_ROUND_KEYS, even_m1, &ctr_m1,
			ctr_inc_m1(even_m1, max_blocks_m1), out, in, nblocks);
    }

  clear_vec_regs();
}


void ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_sm4_riscv_zvksed_cbc_dec (const u32 *rk, byte *out, const byte *in,
				byte *iv_arg, size_t nblocks)
{
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  vuint32m1_t iv;
  SM4_ROUND_KEY_VARIABLES;

  SM4_LOAD_ROUND_KEYS(rk);

  iv = load_u32_m1(iv_arg, 4);

  if (nblocks > max_blocks_m2)
    {
      vbool16_t even_m4 = even_mask_m4();
      vuint32m4_t ivs_m4 = __riscv_vundefined_u32m4();

      while (nblocks >= max_blocks_m4)
	{
	  sm4_cbc_dec_blocks_m4(SM4_ROUND_KEYS, even_m4, &iv, &ivs_m4, out, in,
				max_blocks_m4);
	  SM4_NEXT_BLOCKS(max_blocks_m4);
	}
      if (nblocks > max_blocks_m2)
	{
	  sm4_cbc_dec_blocks_m4(SM4_ROUND_KEYS, even_m4, &iv, &ivs_m4, out, in,
				nblocks);
	  SM4_NEXT_BLOCKS(nblocks);
	}
    }
  if (nblocks > max_blocks_m1)
    {
      vuint32m2_t ivs_m2 = __riscv_vundefined_u32m2();

      sm4_cbc_dec_blocks_m2(SM4_ROUND_KEYS, even_mask_m2(), &iv, &ivs_m2, out,
			    in, nblocks);
    }
  else if (nblocks)
    {
      vuint32m1_t ivs_m1 = __riscv_vundefined_u32m1();

      sm4_cbc_dec_blocks_m1(SM4_ROUND_KEYS, even_mask_m1(), &iv, &ivs_m1, out,
			    in, nblocks);
    }

  store_u32_m1(iv_arg, iv, 4);

  clear_vec_regs();
}


void ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_sm4_riscv_zvksed_cfb_dec (const u32 *rk, byte *out, const byte *in,
				byte *iv_arg, size_t nblocks)
{
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  vuint32m1_t iv;
  SM4_ROUND_KEY_VARIABLES;

  SM4_LOAD_ROUND_KEYS(rk);

  iv = load_u32_m1(iv_arg, 4);

  if (nblocks > max_blocks_m2)
    {
      vbool16_t even_m4 = even_mask_m4();
      vuint32m4_t ivs_m4 = __riscv_vundefined_u32m4();

      while (nblocks >= max_blocks_m4)
	{
	  sm4_cfb_dec_blocks_m4(SM4_ROUND_KEYS, even_m4, &iv, &ivs_m4, out, in,
				max_blocks_m4);
	  SM4_NEXT_BLOCKS(max_blocks_m4);
	}
      if (nblocks > max_blocks_m2)
	{
	  sm4_cfb_dec_blocks_m4(SM4_ROUND_KEYS, even_m4, &iv, &ivs_m4, out, in,
				nblocks);
	  SM4_NEXT_BLOCKS(nblocks);
	}
    }
  if (nblocks > max_blocks_m1)
    {
      vuint32m2_t ivs_m2 = __riscv_vundefined_u32m2();

      sm4_cfb_dec_blocks_m2(SM4_ROUND_KEYS, even_mask_m2(), &iv, &ivs_m2, out,
			    in, nblocks);
    }
  else if (nblocks)
    {
      vuint32m1_t ivs_m1 = __riscv_vundefined_u32m1();

      sm4_cfb_dec_blocks_m1(SM4_ROUND_KEYS, even_mask_m1(), &iv, &ivs_m1, out,
			    in, nblocks);
    }

  store_u32_m1(iv_arg, iv, 4);

  clear_vec_regs();
}


#define SM4_EXPAND_KEY_ROUNDS(rnd) \
  k = __riscv_vsm4k_vi_u32m1(k, rnd, vl); \
  __riscv_vse32_v_u32m1(rk_enc + (rnd) * 4, k, vl); \
  __riscv_vsse32_v_u32m1(rk_dec + 31 - (rnd) * 4, -4, k, vl)

void ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_sm4_riscv_zvksed_expand_key (const byte *key, u32 *rk_enc, u32 *rk_dec,
				   const u32 *fk)
{
  size_t vl = 4;
  vuint32m1_t k;

  k = __riscv_vrev8_v_u32m1(load_u32_m1(key, vl), vl);
  k = __riscv_vxor_vv_u32m1(k, __riscv_vle32_v_u32m1(fk, vl), vl);

  SM4_EXPAND_KEY_ROUNDS(0);
  SM4_EXPAND_KEY_ROUNDS(1);
  SM4_EXPAND_KEY_ROUNDS(2);
  SM4_EXPAND_KEY_ROUNDS(3);
  SM4_EXPAND_KEY_ROUNDS(4);
  SM4_EXPAND_KEY_ROUNDS(5);
  SM4_EXPAND_KEY_ROUNDS(6);
  SM4_EXPAND_KEY_ROUNDS(7);

  clear_vec_regs();
}


unsigned int ASM_FUNC_ATTR FUNC_ATTR_OPT_O2
_gcry_sm4_riscv_v_check_hw(void)
{
  return (__riscv_vsetvl_e32m1(4) == 4);
}

#endif /* HAVE_COMPATIBLE_CC_RISCV_VECTOR_INTRINSICS */
