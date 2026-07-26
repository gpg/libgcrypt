/* rijndael-riscv-zvkned.c - RISC-V vector crypto implementation of AES
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

#include <config.h>

#if defined (__riscv) && \
    defined(HAVE_COMPATIBLE_CC_RISCV_VECTOR_INTRINSICS) && \
    defined(HAVE_COMPATIBLE_CC_RISCV_VECTOR_CRYPTO_INTRINSICS)

#include "g10lib.h"
#include "simd-common-riscv.h"
#include "rijndael-internal.h"
#include "cipher-internal.h"

#include <riscv_vector.h>


#define ALWAYS_INLINE inline __attribute__((always_inline))
#define NO_INLINE __attribute__((noinline))
#define NO_INSTRUMENT_FUNCTION __attribute__((no_instrument_function))

#define ASM_FUNC_ATTR          NO_INSTRUMENT_FUNCTION
#define ASM_FUNC_ATTR_INLINE   ALWAYS_INLINE ASM_FUNC_ATTR
#define ASM_FUNC_ATTR_NOINLINE NO_INLINE ASM_FUNC_ATTR

#ifdef HAVE_GCC_ATTRIBUTE_OPTIMIZE
# define FUNC_ATTR_OPT_O2 __attribute__((optimize("-O2")))
#else
# define FUNC_ATTR_OPT_O2
#endif


/*
 * Helper macro and functions
 */

#define cast_u8m1_u32m1(a) __riscv_vreinterpret_v_u8m1_u32m1(a)
#define cast_u32m1_u8m1(a) __riscv_vreinterpret_v_u32m1_u8m1(a)
#define cast_u32m1_u64m1(a) __riscv_vreinterpret_v_u32m1_u64m1(a)
#define cast_u64m1_u8m1(a) __riscv_vreinterpret_v_u64m1_u8m1(a)

#define cast_u8m2_u32m2(a) __riscv_vreinterpret_v_u8m2_u32m2(a)
#define cast_u32m2_u8m2(a) __riscv_vreinterpret_v_u32m2_u8m2(a)
#define cast_u32m2_u64m2(a) __riscv_vreinterpret_v_u32m2_u64m2(a)
#define cast_u64m2_u32m2(a) __riscv_vreinterpret_v_u64m2_u32m2(a)

#define cast_u8m4_u32m4(a) __riscv_vreinterpret_v_u8m4_u32m4(a)
#define cast_u32m4_u8m4(a) __riscv_vreinterpret_v_u32m4_u8m4(a)
#define cast_u32m4_u64m4(a) __riscv_vreinterpret_v_u32m4_u64m4(a)
#define cast_u64m4_u32m4(a) __riscv_vreinterpret_v_u64m4_u32m4(a)

#define cast_u64m1_u32m1(a) __riscv_vreinterpret_v_u64m1_u32m1(a)
#define cast_u32m1_u64m1(a) __riscv_vreinterpret_v_u32m1_u64m1(a)


static ASM_FUNC_ATTR_INLINE vuint32m1_t
broadcast128_u32m1_u32m1(vuint32m1_t vec, size_t vl_u32)
{
  vuint32m1_t vdst = __riscv_vmv_v_x_u32m1(0, vl_u32);
#ifdef HAVE_BROKEN_VAES_VS_INTRINSIC
  asm ( "vsetvli zero,%[vl],e32,m1,ta,ma;\n\t"
	"vaesz.vs %[dst],%[src];\n\t"
	: [dst] "+vr" (vdst)
	: [vl] "r" (vl_u32), [src] "vr" (vec)
	: "vl", "vtype");
  return vdst;
#else
  return __riscv_vaesz_vs_u32m1_u32m1(vdst, vec, vl_u32);
#endif
}

static ASM_FUNC_ATTR_INLINE vuint32m1_t
unaligned_load_u32m1(const void *ptr, size_t vl_u32)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  return cast_u8m1_u32m1(__riscv_vle8_v_u8m1(ptr, vl_u32 * 4));
#else
  return __riscv_vle32_v_u32m1(ptr, vl_u32);
#endif
}

static ASM_FUNC_ATTR_INLINE void
unaligned_store_u32m1(void *ptr, vuint32m1_t vec, size_t vl_u32)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  __riscv_vse8_v_u8m1(ptr, cast_u32m1_u8m1(vec), vl_u32 * 4);
#else
  __riscv_vse32_v_u32m1(ptr, vec, vl_u32);
#endif
}

static ASM_FUNC_ATTR_INLINE vuint32m2_t
unaligned_load_u32m2(const void *ptr, size_t vl_u32)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  return cast_u8m2_u32m2(__riscv_vle8_v_u8m2(ptr, vl_u32 * 4));
#else
  return __riscv_vle32_v_u32m2(ptr, vl_u32);
#endif
}

static ASM_FUNC_ATTR_INLINE void
unaligned_store_u32m2(void *ptr, vuint32m2_t vec, size_t vl_u32)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  __riscv_vse8_v_u8m2(ptr, cast_u32m2_u8m2(vec), vl_u32 * 4);
#else
  __riscv_vse32_v_u32m2(ptr, vec, vl_u32);
#endif
}

static ASM_FUNC_ATTR_INLINE vuint32m4_t
unaligned_load_u32m4(const void *ptr, size_t vl_u32)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  return cast_u8m4_u32m4(__riscv_vle8_v_u8m4(ptr, vl_u32 * 4));
#else
  return __riscv_vle32_v_u32m4(ptr, vl_u32);
#endif
}

static ASM_FUNC_ATTR_INLINE void
unaligned_store_u32m4(void *ptr, vuint32m4_t vec, size_t vl_u32)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  __riscv_vse8_v_u8m4(ptr, cast_u32m4_u8m4(vec), vl_u32 * 4);
#else
  __riscv_vse32_v_u32m4(ptr, vec, vl_u32);
#endif
}

static ASM_FUNC_ATTR_INLINE size_t
nblocks_to_nblocks_per_m1(size_t max_blocks_m1, size_t nblocks)
{
  return nblocks < max_blocks_m1 ? nblocks : max_blocks_m1;
}


/*
 * HW support detection
 */

int ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_aes_riscv_zvkned_setup_acceleration(RIJNDAEL_context *ctx)
{
  (void)ctx;
  return (__riscv_vsetvl_e32m1(4) == 4);
}


/*
 * Key expansion
 */

static ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
aes128_riscv_setkey (RIJNDAEL_context *ctx, const byte *key)
{
  size_t vl = 4;

  vuint32m1_t round_key = unaligned_load_u32m1 (key, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[0][0], round_key, vl);

  round_key = __riscv_vaeskf1_vi_u32m1 (round_key, 1, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[1][0], round_key, vl);

  round_key = __riscv_vaeskf1_vi_u32m1 (round_key, 2, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[2][0], round_key, vl);

  round_key = __riscv_vaeskf1_vi_u32m1 (round_key, 3, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[3][0], round_key, vl);

  round_key = __riscv_vaeskf1_vi_u32m1 (round_key, 4, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[4][0], round_key, vl);

  round_key = __riscv_vaeskf1_vi_u32m1 (round_key, 5, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[5][0], round_key, vl);

  round_key = __riscv_vaeskf1_vi_u32m1 (round_key, 6, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[6][0], round_key, vl);

  round_key = __riscv_vaeskf1_vi_u32m1 (round_key, 7, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[7][0], round_key, vl);

  round_key = __riscv_vaeskf1_vi_u32m1 (round_key, 8, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[8][0], round_key, vl);

  round_key = __riscv_vaeskf1_vi_u32m1 (round_key, 9, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[9][0], round_key, vl);

  round_key = __riscv_vaeskf1_vi_u32m1 (round_key, 10, vl);
  __riscv_vse32_v_u32m1 (&ctx->keyschenc32[10][0], round_key, vl);

  clear_vec_regs();
}

static ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
aes192_riscv_setkey (RIJNDAEL_context *ctx, const byte *key)
{
  size_t vl = 4;
  u32 *w = &ctx->keyschenc32[0][0];
  u32 wr;
  vuint32m1_t rk_0_7;
  vuint32m1_t rk_4_11;

  rk_0_7 = unaligned_load_u32m1 (&key[0], vl);
  rk_4_11 = unaligned_load_u32m1 (&key[8], vl);
  __riscv_vse32_v_u32m1 (&w[0], rk_0_7, vl);
  __riscv_vse32_v_u32m1 (&w[2], rk_4_11, vl);

#define AES192_KF1_GEN(out, input, round192, vl) \
  ({ \
      vuint32m1_t temp_vec = __riscv_vmv_v_x_u32m1(0, (vl)); \
      temp_vec = __riscv_vslide1down_vx_u32m1(temp_vec, (input), (vl)); \
      temp_vec = __riscv_vaeskf1_vi_u32m1(temp_vec, (round192), (vl)); \
      (out) = __riscv_vmv_x_s_u32m1_u32(temp_vec); \
  })

#define AES192_EXPAND_BLOCK(w, round192, wr, last) \
  ({ \
    (w)[(round192) * 6 + 0] = (w)[(round192) * 6 - 6] ^ (wr); \
    (w)[(round192) * 6 + 1] = (w)[(round192) * 6 - 5] ^ (w)[(round192) * 6 + 0]; \
    (w)[(round192) * 6 + 2] = (w)[(round192) * 6 - 4] ^ (w)[(round192) * 6 + 1]; \
    (w)[(round192) * 6 + 3] = (w)[(round192) * 6 - 3] ^ (w)[(round192) * 6 + 2]; \
    if (!(last)) \
      { \
	(w)[(round192) * 6 + 4] = (w)[(round192) * 6 - 2] ^ (w)[(round192) * 6 + 3]; \
	(w)[(round192) * 6 + 5] = (w)[(round192) * 6 - 1] ^ (w)[(round192) * 6 + 4]; \
      } \
  })

  AES192_KF1_GEN(wr, w[5], 1, vl);
  AES192_EXPAND_BLOCK(w, 1, wr, 0);

  AES192_KF1_GEN(wr, w[11], 2, vl);
  AES192_EXPAND_BLOCK(w, 2, wr, 0);

  AES192_KF1_GEN(wr, w[17], 3, vl);
  AES192_EXPAND_BLOCK(w, 3, wr, 0);

  AES192_KF1_GEN(wr, w[23], 4, vl);
  AES192_EXPAND_BLOCK(w, 4, wr, 0);

  AES192_KF1_GEN(wr, w[29], 5, vl);
  AES192_EXPAND_BLOCK(w, 5, wr, 0);

  AES192_KF1_GEN(wr, w[35], 6, vl);
  AES192_EXPAND_BLOCK(w, 6, wr, 0);

  AES192_KF1_GEN(wr, w[41], 7, vl);
  AES192_EXPAND_BLOCK(w, 7, wr, 0);

  AES192_KF1_GEN(wr, w[47], 8, vl);
  AES192_EXPAND_BLOCK(w, 8, wr, 1);

#undef AES192_KF1_GEN
#undef AES192_EXPAND_BLOCK

  clear_vec_regs();
}

static ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
aes256_riscv_setkey (RIJNDAEL_context *ctx, const byte *key)
{
  size_t vl = 4;

  vuint32m1_t rk_a = unaligned_load_u32m1 (&key[0], vl);
  vuint32m1_t rk_b = unaligned_load_u32m1 (&key[16], vl);

  __riscv_vse32_v_u32m1(&ctx->keyschenc32[0][0], rk_a, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[1][0], rk_b, vl);

  rk_a = __riscv_vaeskf2_vi_u32m1(rk_a, rk_b, 2, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[2][0], rk_a, vl);

  rk_b = __riscv_vaeskf2_vi_u32m1(rk_b, rk_a, 3, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[3][0], rk_b, vl);

  rk_a = __riscv_vaeskf2_vi_u32m1(rk_a, rk_b, 4, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[4][0], rk_a, vl);

  rk_b = __riscv_vaeskf2_vi_u32m1(rk_b, rk_a, 5, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[5][0], rk_b, vl);

  rk_a = __riscv_vaeskf2_vi_u32m1(rk_a, rk_b, 6, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[6][0], rk_a, vl);

  rk_b = __riscv_vaeskf2_vi_u32m1(rk_b, rk_a, 7, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[7][0], rk_b, vl);

  rk_a = __riscv_vaeskf2_vi_u32m1(rk_a, rk_b, 8, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[8][0], rk_a, vl);

  rk_b = __riscv_vaeskf2_vi_u32m1(rk_b, rk_a, 9, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[9][0], rk_b, vl);

  rk_a = __riscv_vaeskf2_vi_u32m1(rk_a, rk_b, 10, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[10][0], rk_a, vl);

  rk_b = __riscv_vaeskf2_vi_u32m1(rk_b, rk_a, 11, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[11][0], rk_b, vl);

  rk_a = __riscv_vaeskf2_vi_u32m1(rk_a, rk_b, 12, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[12][0], rk_a, vl);

  rk_b = __riscv_vaeskf2_vi_u32m1(rk_b, rk_a, 13, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[13][0], rk_b, vl);

  rk_a = __riscv_vaeskf2_vi_u32m1(rk_a, rk_b, 14, vl);
  __riscv_vse32_v_u32m1(&ctx->keyschenc32[14][0], rk_a, vl);

  clear_vec_regs();
}

void ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_aes_riscv_zvkned_setkey (RIJNDAEL_context *ctx, const byte *key)
{
  unsigned int rounds = ctx->rounds;

  if (rounds < 12)
    {
      aes128_riscv_setkey(ctx, key);
    }
  else if (rounds == 12)
    {
      aes192_riscv_setkey(ctx, key);
      _gcry_burn_stack(64);
    }
  else
    {
      aes256_riscv_setkey(ctx, key);
    }
}

static ASM_FUNC_ATTR_INLINE void
do_prepare_decryption(RIJNDAEL_context *ctx)
{
  u32 *ekey = (u32 *)(void *)ctx->keyschenc;
  u32 *dkey = (u32 *)(void *)ctx->keyschdec;
  int rounds = ctx->rounds;
  size_t vl = 4;
  vuint32m1_t k0, k1, k2, k3, k4, k5, k6, k7;
  vuint32m1_t k8, k9, k10, k11, k12, k13, k14;

#define READ_KEY(n) (k##n = __riscv_vle32_v_u32m1(ekey + (rounds - n) * 4, vl))
#define WRITE_KEY(n) __riscv_vse32_v_u32m1(dkey + n * 4, k##n, vl)

  k11 = __riscv_vundefined_u32m1();
  k12 = __riscv_vundefined_u32m1();
  k13 = __riscv_vundefined_u32m1();
  k14 = __riscv_vundefined_u32m1();
  READ_KEY(0); READ_KEY(1);
  READ_KEY(2); READ_KEY(3);
  READ_KEY(4); READ_KEY(5);
  READ_KEY(6); READ_KEY(7);
  READ_KEY(8); READ_KEY(9);
  if (LIKELY(rounds >= 12))
    {
      READ_KEY(10); READ_KEY(11);
      if (LIKELY(rounds > 12))
	{
	  READ_KEY(12); READ_KEY(13);
	  READ_KEY(14);
	}
      else
	{
	  READ_KEY(12);
	}
    }
  else
    {
      READ_KEY(10);
    }

  WRITE_KEY(0); WRITE_KEY(1);
  WRITE_KEY(2); WRITE_KEY(3);
  WRITE_KEY(4); WRITE_KEY(5);
  WRITE_KEY(6); WRITE_KEY(7);
  WRITE_KEY(8); WRITE_KEY(9);
  if (LIKELY(rounds >= 12))
    {
      WRITE_KEY(10); WRITE_KEY(11);
      if (LIKELY(rounds > 12))
	{
	  WRITE_KEY(12); WRITE_KEY(13);
	  WRITE_KEY(14);
	}
      else
	{
	  WRITE_KEY(12);
	}
    }
  else
    {
      WRITE_KEY(10);
    }

#undef READ_KEY
#undef WRITE_KEY
}

void ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_aes_riscv_zvkned_prepare_decryption(RIJNDAEL_context *ctx)
{
  do_prepare_decryption(ctx);
  clear_vec_regs();
}


/*
 * Encryption / Decryption
 */

#define ROUND_KEY_VARIABLES \
  vuint32m1_t rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8, rk9, rk_last
#define ROUND_KEY_VARIABLES_RK10_13 \
  vuint32m1_t rk10, rk11, rk12, rk13

#define LOAD_KEY(tempvec, roundnum) \
  tempvec = __riscv_vle32_v_u32m1(rk + roundnum * 4, BLOCKSIZE / 4)

#define GET_PRELOADED_KEY(tempvec, roundnum) \
  tempvec = rk ## roundnum

#define PRELOAD_ROUND_KEYS(rk, nrounds) \
  ({ \
    LOAD_KEY(rk0, 0); \
    LOAD_KEY(rk1, 1); \
    LOAD_KEY(rk2, 2); \
    LOAD_KEY(rk3, 3); \
    LOAD_KEY(rk4, 4); \
    LOAD_KEY(rk5, 5); \
    LOAD_KEY(rk6, 6); \
    LOAD_KEY(rk7, 7); \
    LOAD_KEY(rk8, 8); \
    LOAD_KEY(rk9, 9); \
    LOAD_KEY(rk_last, nrounds); \
  })

#define PRELOAD_ROUND_KEYS_RK10_13(rk, nrounds) \
  ({ \
    if (LIKELY((nrounds) >= 12)) \
      { \
	LOAD_KEY(rk10, 10); \
	LOAD_KEY(rk11, 11); \
	if (LIKELY((nrounds) > 12)) \
	  { \
	    LOAD_KEY(rk12, 12); \
	    LOAD_KEY(rk13, 13); \
	  } \
	else \
	  { \
	    rk12 = __riscv_vundefined_u32m1(); \
	    rk13 = __riscv_vundefined_u32m1(); \
	  } \
      } \
    else \
      { \
	rk10 = __riscv_vundefined_u32m1(); \
	rk11 = __riscv_vundefined_u32m1(); \
	rk12 = __riscv_vundefined_u32m1(); \
	rk13 = __riscv_vundefined_u32m1(); \
      } \
  })

#ifdef HAVE_BROKEN_VAES_VS_INTRINSIC
#define AES_CRYPT(e_d, mx, load_key, rk, nrounds, blk, vlen) \
  ({ \
    asm ( "vsetvli zero,%[vl],e32,"#mx",ta,ma;\n\t" \
	  "vaesz.vs %[block],%[rk0];\n\t" \
	  "vaes"#e_d"m.vs %[block],%[rk1];\n\t" \
	  "vaes"#e_d"m.vs %[block],%[rk2];\n\t" \
	  "vaes"#e_d"m.vs %[block],%[rk3];\n\t" \
	  "vaes"#e_d"m.vs %[block],%[rk4];\n\t" \
	  "vaes"#e_d"m.vs %[block],%[rk5];\n\t" \
	  "vaes"#e_d"m.vs %[block],%[rk6];\n\t" \
	  "vaes"#e_d"m.vs %[block],%[rk7];\n\t" \
	  "vaes"#e_d"m.vs %[block],%[rk8];\n\t" \
	  "vaes"#e_d"m.vs %[block],%[rk9];\n\t" \
	  : [block] "+vr" (blk) \
	  : [vl] "r" (vlen), \
	    [rk0] "vr" (rk0), [rk1] "vr" (rk1), [rk2] "vr" (rk2), \
	    [rk3] "vr" (rk3), [rk4] "vr" (rk4), [rk5] "vr" (rk5), \
	    [rk6] "vr" (rk6), [rk7] "vr" (rk7), [rk8] "vr" (rk8), \
	    [rk9] "vr" (rk9) \
	  : "vl", "vtype"); \
    if (LIKELY((nrounds) >= 12)) \
      { \
	vuint32m1_t tmp_rk10; \
	vuint32m1_t tmp_rk11; \
	load_key(tmp_rk10, 10); \
	load_key(tmp_rk11, 11); \
	asm ( "vsetvli zero,%[vl],e32,"#mx",ta,ma;\n\t" \
	      "vaes"#e_d"m.vs %[block],%[rk10];\n\t" \
	      "vaes"#e_d"m.vs %[block],%[rk11];\n\t" \
	      : [block] "+vr" (blk) \
	      : [vl] "r" (vlen), \
		[rk10] "vr" (tmp_rk10), [rk11] "vr" (tmp_rk11) \
	      : "vl", "vtype"); \
	if (LIKELY((nrounds) > 12)) \
	  { \
	    vuint32m1_t tmp_rk12; \
	    vuint32m1_t tmp_rk13; \
	    load_key(tmp_rk12, 12); \
	    load_key(tmp_rk13, 13); \
	    asm ( "vsetvli zero,%[vl],e32,"#mx",ta,ma;\n\t" \
		  "vaes"#e_d"m.vs %[block],%[rk12];\n\t" \
		  "vaes"#e_d"m.vs %[block],%[rk13];\n\t" \
		  : [block] "+vr" (blk) \
		  : [vl] "r" (vlen), \
		    [rk12] "vr" (tmp_rk12), [rk13] "vr" (tmp_rk13) \
		  : "vl", "vtype"); \
	  } \
      } \
    asm ( "vsetvli zero,%[vl],e32,"#mx",ta,ma;\n\t" \
	  "vaes"#e_d"f.vs %[block],%[rk_last];\n\t" \
	  : [block] "+vr" (blk) \
	  : [vl] "r" (vlen), [rk_last] "vr" (rk_last) \
	  : "vl", "vtype"); \
  })
#else
#define AES_CRYPT(e_d, mx, load_key, rk, nrounds, block, vl) \
  ({ \
    (block) = __riscv_vaesz_vs_u32m1_u32##mx((block), rk0, (vl)); \
    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk1, (vl)); \
    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk2, (vl)); \
    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk3, (vl)); \
    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk4, (vl)); \
    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk5, (vl)); \
    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk6, (vl)); \
    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk7, (vl)); \
    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk8, (vl)); \
    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk9, (vl)); \
    if (LIKELY((nrounds) >= 12)) \
      { \
	vuint32m1_t tmp_rk10; \
	vuint32m1_t tmp_rk11; \
	load_key(tmp_rk10, 10); \
	load_key(tmp_rk11, 11); \
	(block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), tmp_rk10, (vl)); \
	(block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), tmp_rk11, (vl)); \
	if (LIKELY((nrounds) > 12)) \
	  { \
	    vuint32m1_t tmp_rk12; \
	    vuint32m1_t tmp_rk13; \
	    load_key(tmp_rk12, 12); \
	    load_key(tmp_rk13, 13); \
	    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), tmp_rk12, (vl)); \
	    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), tmp_rk13, (vl)); \
	  } \
      } \
    (block) = __riscv_vaes##e_d##f_vs_u32m1_u32##mx((block), rk_last, (vl)); \
  })
#endif

unsigned int ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_aes_riscv_zvkned_encrypt (const RIJNDAEL_context *ctx, unsigned char *out,
				const unsigned char *in)
{
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  vuint32m1_t block;
  ROUND_KEY_VARIABLES;

  PRELOAD_ROUND_KEYS (rk, rounds);

  block = unaligned_load_u32m1(in, vl);

  AES_CRYPT(e, m1, LOAD_KEY, rk, rounds, block, vl);

  unaligned_store_u32m1(out, block, vl);

  clear_vec_regs();

  return 0; /* does not use stack */
}

unsigned int ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_aes_riscv_zvkned_decrypt (const RIJNDAEL_context *ctx, unsigned char *out,
				const unsigned char *in)
{
  const u32 *rk = ctx->keyschdec32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  vuint32m1_t block;
  ROUND_KEY_VARIABLES;

  PRELOAD_ROUND_KEYS (rk, rounds);

  block = unaligned_load_u32m1(in, vl);

  AES_CRYPT(d, m1, LOAD_KEY, rk, rounds, block, vl);

  unaligned_store_u32m1(out, block, vl);

  clear_vec_regs();

  return 0; /* does not use stack */
}

static ASM_FUNC_ATTR_INLINE void
aes_riscv_zvkned_ecb_crypt (void *context, void *outbuf_arg,
			    const void *inbuf_arg, size_t nblocks, int encrypt)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = encrypt ? ctx->keyschenc32[0] : ctx->keyschdec32[0];
  int rounds = ctx->rounds;
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  ROUND_KEY_VARIABLES;
  ROUND_KEY_VARIABLES_RK10_13;

  if (!encrypt && UNLIKELY(!ctx->decryption_prepared))
    {
      do_prepare_decryption(ctx);
      ctx->decryption_prepared = 1;
    }

  PRELOAD_ROUND_KEYS (rk, rounds);

  while (nblocks >= max_blocks_m4)
    {
      size_t vl_m4 = max_blocks_m4 * 4;
      vuint32m4_t blocks;

      blocks = unaligned_load_u32m4(inbuf, vl_m4);

      if (encrypt)
	AES_CRYPT(e, m4, LOAD_KEY, rk, rounds, blocks, vl_m4);
      else
	AES_CRYPT(d, m4, LOAD_KEY, rk, rounds, blocks, vl_m4);

      unaligned_store_u32m4(outbuf, blocks, vl_m4);

      nblocks -= max_blocks_m4;
      inbuf += BLOCKSIZE * max_blocks_m4;
      outbuf += BLOCKSIZE * max_blocks_m4;
    }

  if (nblocks)
    PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

  if (nblocks && nblocks >= max_blocks_m2)
    {
      size_t vl_m2 = max_blocks_m2 * 4;
      vuint32m2_t blocks;

      blocks = unaligned_load_u32m2(inbuf, vl_m2);

      if (encrypt)
	AES_CRYPT(e, m2, GET_PRELOADED_KEY, rk, rounds, blocks, vl_m2);
      else
	AES_CRYPT(d, m2, GET_PRELOADED_KEY, rk, rounds, blocks, vl_m2);

      unaligned_store_u32m2(outbuf, blocks, vl_m2);

      nblocks -= max_blocks_m2;
      inbuf += BLOCKSIZE * max_blocks_m2;
      outbuf += BLOCKSIZE * max_blocks_m2;
    }

  while (nblocks)
    {
      size_t curr_nblks = nblocks_to_nblocks_per_m1(max_blocks_m1, nblocks);
      size_t vl_m1 = curr_nblks * 4;
      vuint32m1_t blocks;

      blocks = unaligned_load_u32m1(inbuf, vl_m1);

      if (encrypt)
	AES_CRYPT(e, m1, GET_PRELOADED_KEY, rk, rounds, blocks, vl_m1);
      else
	AES_CRYPT(d, m1, GET_PRELOADED_KEY, rk, rounds, blocks, vl_m1);

      unaligned_store_u32m1(outbuf, blocks, vl_m1);

      nblocks -= curr_nblks;
      inbuf += BLOCKSIZE * curr_nblks;
      outbuf += BLOCKSIZE * curr_nblks;
    }

  clear_vec_regs();
}

static void ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
aes_riscv_zvkned_ecb_enc (void *context, void *outbuf_arg,
			  const void *inbuf_arg, size_t nblocks)
{
  aes_riscv_zvkned_ecb_crypt (context, outbuf_arg, inbuf_arg, nblocks, 1);
}

static void ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
aes_riscv_zvkned_ecb_dec (void *context, void *outbuf_arg,
			  const void *inbuf_arg, size_t nblocks)
{
  aes_riscv_zvkned_ecb_crypt (context, outbuf_arg, inbuf_arg, nblocks, 0);
}

void ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_aes_riscv_zvkned_ecb_crypt (void *context, void *outbuf_arg,
				  const void *inbuf_arg, size_t nblocks,
				  int encrypt)
{
  if (encrypt)
    aes_riscv_zvkned_ecb_enc (context, outbuf_arg, inbuf_arg, nblocks);
  else
    aes_riscv_zvkned_ecb_dec (context, outbuf_arg, inbuf_arg, nblocks);
}

ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
_gcry_aes_riscv_zvkned_cfb_enc (void *context, unsigned char *iv_arg,
				void *outbuf_arg, const void *inbuf_arg,
				size_t nblocks)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  vuint32m1_t iv;
  ROUND_KEY_VARIABLES;
  ROUND_KEY_VARIABLES_RK10_13;

  PRELOAD_ROUND_KEYS (rk, rounds);
  PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

  iv = __riscv_vle32_v_u32m1((void *)iv_arg, vl);

  if (nblocks)
    {
      vuint32m1_t data = unaligned_load_u32m1(inbuf, vl);

      while (--nblocks)
	{
	  AES_CRYPT(e, m1, GET_PRELOADED_KEY, rk, rounds, iv, vl);

	  iv = __riscv_vxor_vv_u32m1(iv, data, vl);

	  inbuf += BLOCKSIZE;
	  data = unaligned_load_u32m1(inbuf, vl);

	  unaligned_store_u32m1(outbuf, iv, vl);
	  outbuf += BLOCKSIZE;
	}

      AES_CRYPT(e, m1, GET_PRELOADED_KEY, rk, rounds, iv, vl);

      iv = __riscv_vxor_vv_u32m1(iv, data, vl);

      unaligned_store_u32m1(outbuf, iv, vl);
    }

  __riscv_vse32_v_u32m1((void *)iv_arg, iv, vl);

  clear_vec_regs();
}

ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
_gcry_aes_riscv_zvkned_cbc_enc (void *context, unsigned char *iv_arg,
				void *outbuf_arg, const void *inbuf_arg,
				size_t nblocks, int cbc_mac)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  size_t outbuf_add = (!cbc_mac) * BLOCKSIZE;
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  vuint32m1_t iv;
  ROUND_KEY_VARIABLES;
  ROUND_KEY_VARIABLES_RK10_13;

  PRELOAD_ROUND_KEYS (rk, rounds);
  PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

  iv = __riscv_vle32_v_u32m1((void *)iv_arg, vl);

  if (nblocks)
    {
      vuint32m1_t data = unaligned_load_u32m1(inbuf, vl);

      while (--nblocks)
	{
	  iv = __riscv_vxor_vv_u32m1(data, iv, vl);

	  inbuf += BLOCKSIZE;
	  data = unaligned_load_u32m1(inbuf, vl);

	  AES_CRYPT(e, m1, GET_PRELOADED_KEY, rk, rounds, iv, vl);

	  unaligned_store_u32m1(outbuf, iv, vl);
	  outbuf += outbuf_add;
	}

      iv = __riscv_vxor_vv_u32m1(data, iv, vl);

      AES_CRYPT(e, m1, GET_PRELOADED_KEY, rk, rounds, iv, vl);

      unaligned_store_u32m1(outbuf, iv, vl);
    }

  __riscv_vse32_v_u32m1((void *)iv_arg, iv, vl);

  clear_vec_regs();
}

ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
_gcry_aes_riscv_zvkned_ctr_enc (void *context, unsigned char *ctr_arg,
				void *outbuf_arg, const void *inbuf_arg,
				size_t nblocks)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t blk_vl32 = BLOCKSIZE / 4;
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  size_t vl32m1 = max_blocks_m1 * 4;
  size_t vl32m2 = max_blocks_m2 * 4;
  size_t vl32m4 = max_blocks_m4 * 4;
  vuint32m1_t ctr;
  vbool32_t lane3_mask_m1;
  vuint32m1_t ctrle_m1;
  u32 ctrlow;
  ROUND_KEY_VARIABLES;
  ROUND_KEY_VARIABLES_RK10_13;

  PRELOAD_ROUND_KEYS (rk, rounds);

  ctrlow = ctr_arg[15] + (ctr_arg[14] << 8);
  ctrlow += nblocks;

  /* Prepare full m1 wide counter */
  lane3_mask_m1 = __riscv_vmseq_vx_u32m1_b32(
    __riscv_vand_vx_u32m1(__riscv_vid_v_u32m1(vl32m1), 3, vl32m1), 3,
    vl32m1);
  ctr = __riscv_vle32_v_u32m1((void *)ctr_arg, blk_vl32);
  ctrle_m1 = __riscv_vrev8_v_u32m1(ctr, blk_vl32);
  if (max_blocks_m1 > 1)
    {
      ctrle_m1 = broadcast128_u32m1_u32m1(ctrle_m1, vl32m1);
      ctrle_m1 = __riscv_vadd_vv_u32m1_mu(lane3_mask_m1, ctrle_m1, ctrle_m1,
	__riscv_vsrl_vx_u32m1(__riscv_vid_v_u32m1(vl32m1), 2, vl32m1),
	vl32m1);
    }

  if (nblocks >= max_blocks_m2)
    {
      vbool16_t lane3_mask_m2 = __riscv_vmseq_vx_u32m2_b16(
	__riscv_vand_vx_u32m2(__riscv_vid_v_u32m2(vl32m2), 3, vl32m2), 3,
	vl32m2);
      vuint32m2_t ctrle_m2 = __riscv_vset_v_u32m1_u32m2(
	__riscv_vundefined_u32m2(), 0, ctrle_m1);

      /* Double counter width from m1 to m2 */
      ctrle_m2 = __riscv_vset_v_u32m1_u32m2(ctrle_m2, 1,
	__riscv_vadd_vx_u32m1_mu(lane3_mask_m1, ctrle_m1, ctrle_m1,
				 max_blocks_m1, vl32m1));

      if (nblocks >= max_blocks_m4)
	{
	  vbool8_t lane3_mask_m4 = __riscv_vmseq_vx_u32m4_b8(
	    __riscv_vand_vx_u32m4(__riscv_vid_v_u32m4(vl32m4), 3, vl32m4),
	    3, vl32m4);
	  vuint32m4_t ctrle_m4 = __riscv_vset_v_u32m2_u32m4(
	    __riscv_vundefined_u32m4(), 0, ctrle_m2);

	  /* Double counter width from m2 to m4 */
	  ctrle_m4 = __riscv_vset_v_u32m2_u32m4(ctrle_m4, 1,
	    __riscv_vadd_vx_u32m2_mu(lane3_mask_m2, ctrle_m2, ctrle_m2,
				     max_blocks_m2, vl32m2));

	  do
	    {
	      vuint32m4_t ctr_m4 = __riscv_vrev8_v_u32m4(ctrle_m4, vl32m4);
	      vuint32m4_t data_blks;

	      ctrle_m4 = __riscv_vadd_vx_u32m4_mu(lane3_mask_m4, ctrle_m4,
						  ctrle_m4, max_blocks_m4,
						  vl32m4);

	      data_blks = unaligned_load_u32m4((const void *)inbuf, vl32m4);

	      AES_CRYPT(e, m4, LOAD_KEY, rk, rounds, ctr_m4, vl32m4);

	      data_blks = __riscv_vxor_vv_u32m4(ctr_m4, data_blks, vl32m4);
	      unaligned_store_u32m4((void *)outbuf, data_blks, vl32m4);

	      inbuf += max_blocks_m4 * BLOCKSIZE;
	      outbuf += max_blocks_m4 * BLOCKSIZE;
	      nblocks -= max_blocks_m4;
	    }
	  while (nblocks >= max_blocks_m4);

	  ctrle_m2 = __riscv_vget_v_u32m4_u32m2(ctrle_m4, 0);
	}

      if (nblocks)
	PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

      while (nblocks && nblocks >= max_blocks_m2)
	{
	  vuint32m2_t ctr_m2 = __riscv_vrev8_v_u32m2(ctrle_m2, vl32m2);
	  vuint32m2_t data_blks;

	  ctrle_m2 = __riscv_vadd_vx_u32m2_mu(lane3_mask_m2, ctrle_m2,
					      ctrle_m2, max_blocks_m2, vl32m2);

	  data_blks = unaligned_load_u32m2((const void *)inbuf, vl32m2);

	  AES_CRYPT(e, m2, GET_PRELOADED_KEY, rk, rounds, ctr_m2, vl32m2);

	  data_blks = __riscv_vxor_vv_u32m2(ctr_m2, data_blks, vl32m2);
	  unaligned_store_u32m2((void *)outbuf, data_blks, vl32m2);

	  inbuf += max_blocks_m2 * BLOCKSIZE;
	  outbuf += max_blocks_m2 * BLOCKSIZE;
	  nblocks -= max_blocks_m2;
	}

      ctrle_m1 = __riscv_vget_v_u32m2_u32m1(ctrle_m2, 0);
    }
  else if (nblocks)
    PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

  while (nblocks)
    {
      size_t curr_nblks = nblocks_to_nblocks_per_m1(max_blocks_m1, nblocks);
      vuint32m1_t ctr_m1;
      vuint32m1_t data_blks;

      vl32m1 = curr_nblks * 4;

      ctr_m1 = __riscv_vrev8_v_u32m1(ctrle_m1, vl32m1);
      ctrle_m1 = __riscv_vadd_vx_u32m1_mu(lane3_mask_m1, ctrle_m1, ctrle_m1,
					  curr_nblks, vl32m1);

      data_blks = unaligned_load_u32m1((const void *)inbuf, vl32m1);

      AES_CRYPT(e, m1, GET_PRELOADED_KEY, rk, rounds, ctr_m1, vl32m1);

      data_blks = __riscv_vxor_vv_u32m1(ctr_m1, data_blks, vl32m1);
      unaligned_store_u32m1((void *)outbuf, data_blks, vl32m1);

      inbuf += curr_nblks * BLOCKSIZE;
      outbuf += curr_nblks * BLOCKSIZE;
      nblocks -= curr_nblks;
    }

  ctr_arg[15] = ctrlow;
  ctr_arg[14] = ctrlow >> 8;

  clear_vec_regs();
}

ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
_gcry_aes_riscv_zvkned_ctr32le_enc (void *context, unsigned char *ctr_arg,
				    void *outbuf_arg, const void *inbuf_arg,
				    size_t nblocks)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t blk_vl32 = BLOCKSIZE / 4;
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  size_t vl32m1 = max_blocks_m1 * 4;
  size_t vl32m2 = max_blocks_m2 * 4;
  size_t vl32m4 = max_blocks_m4 * 4;
  vbool32_t lane0_mask_m1;
  vuint32m1_t ctrle_m1;
  u32 ctrlow;
  ROUND_KEY_VARIABLES;
  ROUND_KEY_VARIABLES_RK10_13;

  PRELOAD_ROUND_KEYS (rk, rounds);

  ctrlow = *(u32 *)((void *)ctr_arg);
  ctrlow += nblocks;

  /* Prepare full m1 wide counter */
  ctrle_m1 = __riscv_vle32_v_u32m1((void *)ctr_arg, blk_vl32);
  lane0_mask_m1 = __riscv_vmseq_vx_u32m1_b32(
    __riscv_vand_vx_u32m1(__riscv_vid_v_u32m1(vl32m1), 3, vl32m1), 0,
    vl32m1);
  if (max_blocks_m1 > 1)
    {
      ctrle_m1 = broadcast128_u32m1_u32m1(ctrle_m1, vl32m1);
      ctrle_m1 = __riscv_vadd_vv_u32m1_mu(lane0_mask_m1, ctrle_m1, ctrle_m1,
	__riscv_vsrl_vx_u32m1(__riscv_vid_v_u32m1(vl32m1), 2, vl32m1),
	vl32m1);
    }

  if (nblocks >= max_blocks_m2)
    {
      vbool16_t lane0_mask_m2 = __riscv_vmseq_vx_u32m2_b16(
	__riscv_vand_vx_u32m2(__riscv_vid_v_u32m2(vl32m2), 3, vl32m2), 0,
	vl32m2);
      vuint32m2_t ctrle_m2 = __riscv_vset_v_u32m1_u32m2(
	__riscv_vundefined_u32m2(), 0, ctrle_m1);

      /* Double counter width from m1 to m2 */
      ctrle_m2 = __riscv_vset_v_u32m1_u32m2(ctrle_m2, 1,
	__riscv_vadd_vx_u32m1_mu(lane0_mask_m1, ctrle_m1, ctrle_m1,
				 max_blocks_m1, vl32m1));

      if (nblocks >= max_blocks_m4)
	{
	  vbool8_t lane0_mask_m4 = __riscv_vmseq_vx_u32m4_b8(
	    __riscv_vand_vx_u32m4(__riscv_vid_v_u32m4(vl32m4), 3, vl32m4),
	    0, vl32m4);
	  vuint32m4_t ctrle_m4 = __riscv_vset_v_u32m2_u32m4(
	    __riscv_vundefined_u32m4(), 0, ctrle_m2);

	  /* Double counter width from m2 to m4 */
	  ctrle_m4 = __riscv_vset_v_u32m2_u32m4(ctrle_m4, 1,
	    __riscv_vadd_vx_u32m2_mu(lane0_mask_m2, ctrle_m2, ctrle_m2,
				     max_blocks_m2, vl32m2));

	  do
	    {
	      vuint32m4_t ctr_m4 = ctrle_m4;
	      vuint32m4_t data_blks;

	      ctrle_m4 = __riscv_vadd_vx_u32m4_mu(lane0_mask_m4, ctrle_m4,
						  ctrle_m4, max_blocks_m4,
						  vl32m4);

	      data_blks = unaligned_load_u32m4((const void *)inbuf, vl32m4);

	      AES_CRYPT(e, m4, LOAD_KEY, rk, rounds, ctr_m4, vl32m4);

	      data_blks = __riscv_vxor_vv_u32m4(ctr_m4, data_blks, vl32m4);
	      unaligned_store_u32m4((void *)outbuf, data_blks, vl32m4);

	      inbuf += max_blocks_m4 * BLOCKSIZE;
	      outbuf += max_blocks_m4 * BLOCKSIZE;
	      nblocks -= max_blocks_m4;
	    }
	  while (nblocks >= max_blocks_m4);

	  ctrle_m2 = __riscv_vget_v_u32m4_u32m2(ctrle_m4, 0);
	}

      if (nblocks)
	PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

      while (nblocks && nblocks >= max_blocks_m2)
	{
	  vuint32m2_t ctr_m2 = ctrle_m2;
	  vuint32m2_t data_blks;

	  ctrle_m2 = __riscv_vadd_vx_u32m2_mu(lane0_mask_m2, ctrle_m2,
					      ctrle_m2, max_blocks_m2, vl32m2);

	  data_blks = unaligned_load_u32m2((const void *)inbuf, vl32m2);

	  AES_CRYPT(e, m2, GET_PRELOADED_KEY, rk, rounds, ctr_m2, vl32m2);

	  data_blks = __riscv_vxor_vv_u32m2(ctr_m2, data_blks, vl32m2);
	  unaligned_store_u32m2((void *)outbuf, data_blks, vl32m2);

	  inbuf += max_blocks_m2 * BLOCKSIZE;
	  outbuf += max_blocks_m2 * BLOCKSIZE;
	  nblocks -= max_blocks_m2;
	}

      ctrle_m1 = __riscv_vget_v_u32m2_u32m1(ctrle_m2, 0);
    }
  else if (nblocks)
    PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

  while (nblocks)
    {
      size_t curr_nblks = nblocks_to_nblocks_per_m1(max_blocks_m1, nblocks);
      vuint32m1_t ctr_m1 = ctrle_m1;
      vuint32m1_t data_blks;

      vl32m1 = curr_nblks * 4;

      ctrle_m1 = __riscv_vadd_vx_u32m1_mu(lane0_mask_m1, ctrle_m1, ctrle_m1,
					  curr_nblks, vl32m1);

      data_blks = unaligned_load_u32m1((const void *)inbuf, vl32m1);

      AES_CRYPT(e, m1, GET_PRELOADED_KEY, rk, rounds, ctr_m1, vl32m1);

      data_blks = __riscv_vxor_vv_u32m1(ctr_m1, data_blks, vl32m1);
      unaligned_store_u32m1((void *)outbuf, data_blks, vl32m1);

      inbuf += curr_nblks * BLOCKSIZE;
      outbuf += curr_nblks * BLOCKSIZE;
      nblocks -= curr_nblks;
    }

  *(u32 *)(void *)ctr_arg = ctrlow;

  clear_vec_regs();
}

ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
_gcry_aes_riscv_zvkned_cfb_dec (void *context, unsigned char *iv_arg,
				void *outbuf_arg, const void *inbuf_arg,
				size_t nblocks)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t blk_vl32 = BLOCKSIZE / 4;
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  vuint32m1_t iv;
  vuint32m2_t iv_m2;
  vuint32m4_t iv_m4;
  ROUND_KEY_VARIABLES;
  ROUND_KEY_VARIABLES_RK10_13;

  PRELOAD_ROUND_KEYS (rk, rounds);

  iv = __riscv_vle32_v_u32m1((void *)iv_arg, blk_vl32);

  iv_m4 = __riscv_vundefined_u32m4();
  while (nblocks >= max_blocks_m4)
    {
      size_t vl_m4 = max_blocks_m4 * 4;
      size_t vl_m1 = max_blocks_m1 * 4;
      vuint32m4_t data_blks = unaligned_load_u32m4(inbuf, vl_m4);
      vuint32m1_t new_iv = __riscv_vslidedown_vx_u32m1(
	__riscv_vget_v_u32m4_u32m1(data_blks, 3), vl_m1 - blk_vl32, vl_m1);

      iv_m4 = __riscv_vset_v_u32m1_u32m4(iv_m4, 0, iv);
      iv_m4 = __riscv_vslideup_vx_u32m4(iv_m4, data_blks, blk_vl32, vl_m4);

      iv = new_iv;

      AES_CRYPT(e, m4, LOAD_KEY, rk, rounds, iv_m4, vl_m4);

      data_blks = __riscv_vxor_vv_u32m4(iv_m4, data_blks, vl_m4);
      unaligned_store_u32m4(outbuf, data_blks, vl_m4);

      inbuf += max_blocks_m4 * BLOCKSIZE;
      outbuf += max_blocks_m4 * BLOCKSIZE;
      nblocks -= max_blocks_m4;
    }

  if (nblocks)
    PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

  iv_m2 = __riscv_vundefined_u32m2();
  while (nblocks && nblocks >= max_blocks_m2)
    {
      size_t vl_m2 = max_blocks_m2 * 4;
      size_t vl_m1 = max_blocks_m1 * 4;
      vuint32m2_t data_blks = unaligned_load_u32m2(inbuf, vl_m2);
      vuint32m1_t new_iv = __riscv_vslidedown_vx_u32m1(
	__riscv_vget_v_u32m2_u32m1(data_blks, 1), vl_m1 - blk_vl32, vl_m1);

      iv_m2 = __riscv_vset_v_u32m1_u32m2(iv_m2, 0, iv);
      iv_m2 = __riscv_vslideup_vx_u32m2(iv_m2, data_blks, blk_vl32, vl_m2);

      iv = new_iv;

      AES_CRYPT(e, m2, GET_PRELOADED_KEY, rk, rounds, iv_m2, vl_m2);

      data_blks = __riscv_vxor_vv_u32m2(iv_m2, data_blks, vl_m2);
      unaligned_store_u32m2(outbuf, data_blks, vl_m2);

      inbuf += max_blocks_m2 * BLOCKSIZE;
      outbuf += max_blocks_m2 * BLOCKSIZE;
      nblocks -= max_blocks_m2;
    }

  while (nblocks)
    {
      size_t curr_nblks = nblocks_to_nblocks_per_m1(max_blocks_m1, nblocks);
      size_t vl_m1 = curr_nblks * 4;
      vuint32m1_t data_blks = unaligned_load_u32m1(inbuf, vl_m1);
      vuint32m1_t new_iv = __riscv_vslidedown_vx_u32m1(data_blks,
						       vl_m1 - blk_vl32, vl_m1);
      vuint32m1_t iv_m1 = __riscv_vslideup_vx_u32m1(iv, data_blks, blk_vl32,
						    vl_m1);

      iv = new_iv;

      AES_CRYPT(e, m1, GET_PRELOADED_KEY, rk, rounds, iv_m1, vl_m1);

      data_blks = __riscv_vxor_vv_u32m1(iv_m1, data_blks, vl_m1);
      unaligned_store_u32m1(outbuf, data_blks, vl_m1);

      inbuf += curr_nblks * BLOCKSIZE;
      outbuf += curr_nblks * BLOCKSIZE;
      nblocks -= curr_nblks;
    }

  __riscv_vse32_v_u32m1((void *)iv_arg, iv, blk_vl32);

  clear_vec_regs();
}

ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
_gcry_aes_riscv_zvkned_cbc_dec (void *context, unsigned char *iv_arg,
				void *outbuf_arg, const void *inbuf_arg,
				size_t nblocks)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = ctx->keyschdec32[0];
  int rounds = ctx->rounds;
  size_t blk_vl32 = BLOCKSIZE / 4;
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  vuint32m1_t iv;
  vuint32m2_t iv_m2;
  vuint32m4_t iv_m4;
  ROUND_KEY_VARIABLES;
  ROUND_KEY_VARIABLES_RK10_13;

  if (UNLIKELY(!ctx->decryption_prepared))
    {
      do_prepare_decryption(ctx);
      ctx->decryption_prepared = 1;
    }

  PRELOAD_ROUND_KEYS (rk, rounds);

  iv = __riscv_vle32_v_u32m1((void *)iv_arg, blk_vl32);

  iv_m4 = __riscv_vundefined_u32m4();
  while (nblocks >= max_blocks_m4)
    {
      size_t vl_m4 = max_blocks_m4 * 4;
      size_t vl_m1 = max_blocks_m1 * 4;
      vuint32m4_t data_blks = unaligned_load_u32m4(inbuf, vl_m4);

      iv_m4 = __riscv_vset_v_u32m1_u32m4(iv_m4, 0, iv);
      iv_m4 = __riscv_vslideup_vx_u32m4(iv_m4, data_blks, blk_vl32, vl_m4);

      iv = __riscv_vslidedown_vx_u32m1(
	__riscv_vget_v_u32m4_u32m1(data_blks, 3), vl_m1 - blk_vl32, vl_m1);

      AES_CRYPT(d, m4, LOAD_KEY, rk, rounds, data_blks, vl_m4);

      data_blks = __riscv_vxor_vv_u32m4(iv_m4, data_blks, vl_m4);
      unaligned_store_u32m4(outbuf, data_blks, vl_m4);

      inbuf += max_blocks_m4 * BLOCKSIZE;
      outbuf += max_blocks_m4 * BLOCKSIZE;
      nblocks -= max_blocks_m4;
    }

  if (nblocks)
    PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

  iv_m2 = __riscv_vundefined_u32m2();
  while (nblocks && nblocks >= max_blocks_m2)
    {
      size_t vl_m2 = max_blocks_m2 * 4;
      size_t vl_m1 = max_blocks_m1 * 4;
      vuint32m2_t data_blks = unaligned_load_u32m2(inbuf, vl_m2);

      iv_m2 = __riscv_vset_v_u32m1_u32m2(iv_m2, 0, iv);
      iv_m2 = __riscv_vslideup_vx_u32m2(iv_m2, data_blks, blk_vl32, vl_m2);

      iv = __riscv_vslidedown_vx_u32m1(
	__riscv_vget_v_u32m2_u32m1(data_blks, 1), vl_m1 - blk_vl32, vl_m1);

      AES_CRYPT(d, m2, GET_PRELOADED_KEY, rk, rounds, data_blks, vl_m2);

      data_blks = __riscv_vxor_vv_u32m2(iv_m2, data_blks, vl_m2);
      unaligned_store_u32m2(outbuf, data_blks, vl_m2);

      inbuf += max_blocks_m2 * BLOCKSIZE;
      outbuf += max_blocks_m2 * BLOCKSIZE;
      nblocks -= max_blocks_m2;
    }

  while (nblocks)
    {
      size_t curr_nblks = nblocks_to_nblocks_per_m1(max_blocks_m1, nblocks);
      size_t vl_m1 = curr_nblks * 4;
      vuint32m1_t data_blks = unaligned_load_u32m1(inbuf, vl_m1);
      vuint32m1_t iv_m1 = __riscv_vslideup_vx_u32m1(iv, data_blks, blk_vl32,
						    vl_m1);

      iv = __riscv_vslidedown_vx_u32m1(data_blks, vl_m1 - blk_vl32, vl_m1);

      AES_CRYPT(d, m1, GET_PRELOADED_KEY, rk, rounds, data_blks, vl_m1);

      data_blks = __riscv_vxor_vv_u32m1(iv_m1, data_blks, vl_m1);
      unaligned_store_u32m1(outbuf, data_blks, vl_m1);

      inbuf += curr_nblks * BLOCKSIZE;
      outbuf += curr_nblks * BLOCKSIZE;
      nblocks -= curr_nblks;
    }

  __riscv_vse32_v_u32m1((void *)iv_arg, iv, blk_vl32);

  clear_vec_regs();
}

static ASM_FUNC_ATTR_INLINE vuint32m1_t
ocb_offsets_m1 (gcry_cipher_hd_t c, u64 *np, vuint32m1_t *ivp,
		vuint32m1_t offsets, size_t nblocks, size_t vl_m1)
{
  vuint32m1_t iv = *ivp;
  size_t blk_vl32 = BLOCKSIZE / 4;
  size_t k = 0;

  do
    {
      const void *l = ocb_get_l(c, ++(*np));
      vuint32m1_t l_ntzi = __riscv_vle32_v_u32m1(l, blk_vl32);

      iv = __riscv_vxor_vv_u32m1(iv, l_ntzi, blk_vl32);
      offsets = __riscv_vslideup_vx_u32m1(offsets, iv, k * blk_vl32, vl_m1);
    }
  while (++k < nblocks);

  *ivp = iv;
  return offsets;
}

static ASM_FUNC_ATTR_INLINE FUNC_ATTR_OPT_O2 size_t
aes_riscv_ocb_crypt (gcry_cipher_hd_t c, void *outbuf_arg,
		     const void *inbuf_arg, size_t nblocks, int encrypt)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = encrypt ? ctx->keyschenc32[0] : ctx->keyschdec32[0];
  int auth = encrypt < 0;
  int rounds = ctx->rounds;
  size_t blk_vl32 = BLOCKSIZE / 4;
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  size_t vl_m1 = max_blocks_m1 * 4;
  size_t vl_m2 = max_blocks_m2 * 4;
  size_t vl_m4 = max_blocks_m4 * 4;
  vuint32m1_t iv;
  vuint32m1_t ctr;
  vuint32m1_t offs_m1 = __riscv_vundefined_u32m1();
  size_t h;
  u64 n;
  ROUND_KEY_VARIABLES;
  ROUND_KEY_VARIABLES_RK10_13;

  if (!encrypt && UNLIKELY(!ctx->decryption_prepared))
    {
      do_prepare_decryption(ctx);
      ctx->decryption_prepared = 1;
    }

  PRELOAD_ROUND_KEYS (rk, rounds);

  /* Preload Offset and Checksum */
  if (auth)
    {
      n = c->u_mode.ocb.aad_nblocks;
      iv = __riscv_vle32_v_u32m1((void *)c->u_mode.ocb.aad_offset, blk_vl32);
      ctr = __riscv_vle32_v_u32m1((void *)c->u_mode.ocb.aad_sum, blk_vl32);
    }
  else
    {
      n = c->u_mode.ocb.data_nblocks;
      iv = __riscv_vle32_v_u32m1((void *)c->u_iv.iv, blk_vl32);
      ctr = __riscv_vle32_v_u32m1((void *)c->u_ctr.ctr, blk_vl32);
    }
  ctr = __riscv_vmv_v_v_u32m1_tu(__riscv_vmv_v_x_u32m1(0, vl_m1), ctr,
				 blk_vl32);

  if (nblocks >= max_blocks_m4)
    {
      vuint32m4_t offs_m4 = __riscv_vundefined_u32m4();
      vuint32m4_t ctr_m4 =
	__riscv_vset_v_u32m1_u32m4(__riscv_vmv_v_x_u32m4(0, vl_m4), 0, ctr);
      vuint32m2_t ctr_m2;

      do
	{
	  vuint32m4_t data_blks = unaligned_load_u32m4(inbuf, vl_m4);

	  if (encrypt > 0)
	    {
	      /* Checksum_i = Checksum_{i-1} xor P_i  */
	      ctr_m4 = __riscv_vxor_vv_u32m4(ctr_m4, data_blks, vl_m4);
	    }

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  offs_m1 = ocb_offsets_m1(c, &n, &iv, offs_m1, max_blocks_m1, vl_m1);
	  offs_m4 = __riscv_vset_v_u32m1_u32m4(offs_m4, 0, offs_m1);
	  offs_m1 = ocb_offsets_m1(c, &n, &iv, offs_m1, max_blocks_m1, vl_m1);
	  offs_m4 = __riscv_vset_v_u32m1_u32m4(offs_m4, 1, offs_m1);
	  offs_m1 = ocb_offsets_m1(c, &n, &iv, offs_m1, max_blocks_m1, vl_m1);
	  offs_m4 = __riscv_vset_v_u32m1_u32m4(offs_m4, 2, offs_m1);
	  offs_m1 = ocb_offsets_m1(c, &n, &iv, offs_m1, max_blocks_m1, vl_m1);
	  offs_m4 = __riscv_vset_v_u32m1_u32m4(offs_m4, 3, offs_m1);

	  /* P_i = Offset_i xor CIPHER(K, C_i xor Offset_i)  */
	  data_blks = __riscv_vxor_vv_u32m4(offs_m4, data_blks, vl_m4);

	  if (encrypt)
	    AES_CRYPT(e, m4, LOAD_KEY, rk, rounds, data_blks, vl_m4);
	  else
	    AES_CRYPT(d, m4, LOAD_KEY, rk, rounds, data_blks, vl_m4);

	  if (!auth)
	    {
	      data_blks = __riscv_vxor_vv_u32m4(offs_m4, data_blks, vl_m4);

	      unaligned_store_u32m4(outbuf, data_blks, vl_m4);
	      outbuf += max_blocks_m4 * BLOCKSIZE;
	    }

	  if (encrypt <= 0)
	    {
	      /* Checksum_i = Checksum_{i-1} xor P_i  */
	      ctr_m4 = __riscv_vxor_vv_u32m4(ctr_m4, data_blks, vl_m4);
	    }

	  inbuf += max_blocks_m4 * BLOCKSIZE;
	  nblocks -= max_blocks_m4;
	}
      while (nblocks >= max_blocks_m4);

      /* Checksum_i = Checksum_{i-1} xor P_i  */
      ctr_m2 = __riscv_vxor_vv_u32m2(__riscv_vget_v_u32m4_u32m2(ctr_m4, 0),
				     __riscv_vget_v_u32m4_u32m2(ctr_m4, 1),
				     vl_m2);
      ctr = __riscv_vxor_vv_u32m1(__riscv_vget_v_u32m2_u32m1(ctr_m2, 0),
				  __riscv_vget_v_u32m2_u32m1(ctr_m2, 1),
				  vl_m1);
    }

  if (nblocks)
    PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

  if (nblocks && nblocks >= max_blocks_m2)
    {
      vuint32m2_t offs_m2 = __riscv_vundefined_u32m2();
      vuint32m2_t ctr_m2 =
	__riscv_vset_v_u32m1_u32m2(__riscv_vmv_v_x_u32m2(0, vl_m2), 0, ctr);

      do
	{
	  vuint32m2_t data_blks = unaligned_load_u32m2(inbuf, vl_m2);

	  if (encrypt > 0)
	    {
	      /* Checksum_i = Checksum_{i-1} xor P_i  */
	      ctr_m2 = __riscv_vxor_vv_u32m2(ctr_m2, data_blks, vl_m2);
	    }

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  offs_m1 = ocb_offsets_m1(c, &n, &iv, offs_m1, max_blocks_m1, vl_m1);
	  offs_m2 = __riscv_vset_v_u32m1_u32m2(offs_m2, 0, offs_m1);
	  offs_m1 = ocb_offsets_m1(c, &n, &iv, offs_m1, max_blocks_m1, vl_m1);
	  offs_m2 = __riscv_vset_v_u32m1_u32m2(offs_m2, 1, offs_m1);

	  /* P_i = Offset_i xor CIPHER(K, C_i xor Offset_i)  */
	  data_blks = __riscv_vxor_vv_u32m2(offs_m2, data_blks, vl_m2);

	  if (encrypt)
	    AES_CRYPT(e, m2, GET_PRELOADED_KEY, rk, rounds, data_blks, vl_m2);
	  else
	    AES_CRYPT(d, m2, GET_PRELOADED_KEY, rk, rounds, data_blks, vl_m2);

	  if (!auth)
	    {
	      data_blks = __riscv_vxor_vv_u32m2(offs_m2, data_blks, vl_m2);

	      unaligned_store_u32m2(outbuf, data_blks, vl_m2);
	      outbuf += max_blocks_m2 * BLOCKSIZE;
	    }

	  if (encrypt <= 0)
	    {
	      /* Checksum_i = Checksum_{i-1} xor P_i  */
	      ctr_m2 = __riscv_vxor_vv_u32m2(ctr_m2, data_blks, vl_m2);
	    }

	  inbuf += max_blocks_m2 * BLOCKSIZE;
	  nblocks -= max_blocks_m2;
	}
      while (nblocks >= max_blocks_m2);

      /* Checksum_i = Checksum_{i-1} xor P_i  */
      ctr = __riscv_vxor_vv_u32m1(__riscv_vget_v_u32m2_u32m1(ctr_m2, 0),
				  __riscv_vget_v_u32m2_u32m1(ctr_m2, 1),
				  vl_m1);
    }

  while (nblocks)
    {
      size_t curr_nblks = nblocks_to_nblocks_per_m1(max_blocks_m1, nblocks);
      vuint32m1_t data_blks;

      vl_m1 = curr_nblks * 4;

      data_blks = unaligned_load_u32m1(inbuf, vl_m1);

      if (encrypt > 0)
	{
	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  ctr = __riscv_vxor_vv_u32m1_tu(ctr, ctr, data_blks, vl_m1);
	}

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      offs_m1 = ocb_offsets_m1(c, &n, &iv, offs_m1, curr_nblks, vl_m1);

      /* P_i = Offset_i xor CIPHER(K, C_i xor Offset_i)  */
      data_blks = __riscv_vxor_vv_u32m1(offs_m1, data_blks, vl_m1);

      if (encrypt)
	AES_CRYPT(e, m1, GET_PRELOADED_KEY, rk, rounds, data_blks, vl_m1);
      else
	AES_CRYPT(d, m1, GET_PRELOADED_KEY, rk, rounds, data_blks, vl_m1);

      if (!auth)
	{
	  data_blks = __riscv_vxor_vv_u32m1(offs_m1, data_blks, vl_m1);

	  unaligned_store_u32m1(outbuf, data_blks, vl_m1);
	  outbuf += curr_nblks * BLOCKSIZE;
	}

      if (encrypt <= 0)
	{
	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  ctr = __riscv_vxor_vv_u32m1_tu(ctr, ctr, data_blks, vl_m1);
	}

      inbuf += curr_nblks * BLOCKSIZE;
      nblocks -= curr_nblks;
    }

  for (h = max_blocks_m1; h > 1; h /= 2)
    {
      vuint32m1_t ctr_hi = __riscv_vslidedown_vx_u32m1(ctr, (h / 2) * blk_vl32,
						       h * blk_vl32);
      ctr = __riscv_vxor_vv_u32m1(ctr, ctr_hi, (h / 2) * blk_vl32);
    }

  if (auth)
    {
      c->u_mode.ocb.aad_nblocks = n;
      __riscv_vse32_v_u32m1((void *)c->u_mode.ocb.aad_offset, iv, blk_vl32);
      __riscv_vse32_v_u32m1((void *)c->u_mode.ocb.aad_sum, ctr, blk_vl32);
    }
  else
    {
      c->u_mode.ocb.data_nblocks = n;
      __riscv_vse32_v_u32m1((void *)c->u_iv.iv, iv, blk_vl32);
      __riscv_vse32_v_u32m1((void *)c->u_ctr.ctr, ctr, blk_vl32);
    }

  clear_vec_regs();

  return 0;
}

size_t ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_aes_riscv_zvkned_ocb_crypt (gcry_cipher_hd_t c, void *outbuf_arg,
				  const void *inbuf_arg, size_t nblocks,
				  int encrypt)
{
  if (encrypt)
    return aes_riscv_ocb_crypt(c, outbuf_arg, inbuf_arg, nblocks, 1);
  else
    return aes_riscv_ocb_crypt(c, outbuf_arg, inbuf_arg, nblocks, 0);
}

size_t ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_aes_riscv_zvkned_ocb_auth (gcry_cipher_hd_t c, const void *abuf_arg,
				 size_t nblocks)
{
  return aes_riscv_ocb_crypt(c, NULL, abuf_arg, nblocks, -1);
}

/* 0x87 widens the S-bit overflow by seven bits, which must fit the lane. */
#define XTS_GFMUL_POW_MAX_SHIFT (64 - 7)

/* Multiply each 128-bit lane pair by alpha^S. */
#define DEFINE_XTS_GFMUL_POW(MX, BOOL) \
  static ASM_FUNC_ATTR_INLINE vuint64##MX##_t \
  xts_gfmul_pow1_##MX (vuint64##MX##_t vec_in, vbool##BOOL##_t even, size_t s, \
		       size_t vl) \
  { \
    vuint64##MX##_t hi = __riscv_vsrl_vx_u64##MX(vec_in, 64 - s, vl); \
    vuint64##MX##_t lo = __riscv_vsll_vx_u64##MX(vec_in, s, vl); \
    vuint64##MX##_t sw = __riscv_vslide1up_vx_u64##MX(hi, 0, vl); \
    vuint64##MX##_t acc; \
    \
    sw = __riscv_vslidedown_vx_u64##MX##_mu(even, sw, hi, 1, vl); \
    acc = __riscv_vsll_vx_u64##MX(sw, 5, vl); \
    acc = __riscv_vxor_vv_u64##MX(acc, sw, vl); \
    acc = __riscv_vsll_vx_u64##MX(acc, 1, vl); \
    acc = __riscv_vxor_vv_u64##MX(acc, sw, vl); \
    acc = __riscv_vsll_vx_u64##MX(acc, 1, vl); \
    sw = __riscv_vxor_vv_u64##MX##_mu(even, sw, sw, acc, vl); \
    return __riscv_vxor_vv_u64##MX(lo, sw, vl); \
  } \
  \
  static ASM_FUNC_ATTR_INLINE vuint32##MX##_t \
  xts_gfmul_pow_##MX (vuint32##MX##_t vec_in, vbool##BOOL##_t even, size_t s, \
		      size_t vl_u32) \
  { \
    vuint64##MX##_t vec = cast_u32##MX##_u64##MX(vec_in); \
    size_t vl = vl_u32 / 2; \
    \
    while (UNLIKELY(s > XTS_GFMUL_POW_MAX_SHIFT)) \
      { \
	vec = xts_gfmul_pow1_##MX(vec, even, XTS_GFMUL_POW_MAX_SHIFT, vl); \
	s -= XTS_GFMUL_POW_MAX_SHIFT; \
      } \
    return cast_u64##MX##_u32##MX(xts_gfmul_pow1_##MX(vec, even, s, vl)); \
  }

DEFINE_XTS_GFMUL_POW(m1, 64)
DEFINE_XTS_GFMUL_POW(m2, 32)
DEFINE_XTS_GFMUL_POW(m4, 16)

static ASM_FUNC_ATTR_INLINE FUNC_ATTR_OPT_O2 void
aes_riscv_xts_crypt (void *context, unsigned char *tweak_arg, void *outbuf_arg,
		     const void *inbuf_arg, size_t nblocks, int encrypt)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = encrypt ? ctx->keyschenc32[0] : ctx->keyschdec32[0];
  int rounds = ctx->rounds;
  size_t blk_vl32 = BLOCKSIZE / 4;
  size_t max_blocks_m1 = __riscv_vsetvlmax_e32m1() / 4;
  size_t max_blocks_m2 = max_blocks_m1 * 2;
  size_t max_blocks_m4 = max_blocks_m1 * 4;
  size_t vl64_m1 = max_blocks_m1 * 2;
  size_t vl_m1 = max_blocks_m1 * 4;
  vbool64_t even_m1;
  vuint32m1_t tweak;
  size_t k;
  ROUND_KEY_VARIABLES;
  ROUND_KEY_VARIABLES_RK10_13;

  if (!encrypt && UNLIKELY(!ctx->decryption_prepared))
    {
      do_prepare_decryption(ctx);
      ctx->decryption_prepared = 1;
    }

  PRELOAD_ROUND_KEYS (rk, rounds);

  /* Prepare tweak for full m1. */
  tweak = __riscv_vle32_v_u32m1((void *)tweak_arg, blk_vl32);

  even_m1 = __riscv_vmseq_vx_u64m1_b64(
    __riscv_vand_vx_u64m1(__riscv_vid_v_u64m1(vl64_m1), 1, vl64_m1), 0,
    vl64_m1);

  /* Double the tweak run until m1 is full. */
  for (k = 1; k < max_blocks_m1; k *= 2)
    {
      vuint32m1_t next = xts_gfmul_pow_m1(tweak, even_m1, k, k * blk_vl32);

      tweak = __riscv_vslideup_vx_u32m1(tweak, next, k * blk_vl32,
					2 * k * blk_vl32);
    }

  if (nblocks >= max_blocks_m2)
    {
      size_t vl64_m2 = max_blocks_m2 * 2;
      size_t vl_m2 = max_blocks_m2 * 4;
      vbool32_t even_m2 = __riscv_vmseq_vx_u64m2_b32(
	__riscv_vand_vx_u64m2(__riscv_vid_v_u64m2(vl64_m2), 1, vl64_m2), 0,
	vl64_m2);
      vuint32m2_t tweaks_m2;

      /* Continue doubling from m1 to m2. */
      tweaks_m2 = __riscv_vset_v_u32m1_u32m2(__riscv_vundefined_u32m2(), 0,
					     tweak);
      tweaks_m2 = __riscv_vset_v_u32m1_u32m2(tweaks_m2, 1,
	xts_gfmul_pow_m1(tweak, even_m1, max_blocks_m1, vl_m1));

      if (nblocks >= max_blocks_m4)
	{
	  size_t vl64_m4 = max_blocks_m4 * 2;
	  size_t vl_m4 = max_blocks_m4 * 4;
	  vbool16_t even_m4 = __riscv_vmseq_vx_u64m4_b16(
	    __riscv_vand_vx_u64m4(__riscv_vid_v_u64m4(vl64_m4), 1, vl64_m4),
	    0, vl64_m4);
	  vuint32m4_t tweaks_m4;

	  /* Continue doubling from m2 to m4. */
	  tweaks_m4 = __riscv_vset_v_u32m2_u32m4(
	    __riscv_vundefined_u32m4(), 0, tweaks_m2);
	  tweaks_m4 = __riscv_vset_v_u32m2_u32m4(tweaks_m4, 1,
	    xts_gfmul_pow_m2(tweaks_m2, even_m2, max_blocks_m2, vl_m2));

	  do
	    {
	      vuint32m4_t data_blks = unaligned_load_u32m4(inbuf, vl_m4);

	      data_blks = __riscv_vxor_vv_u32m4(tweaks_m4, data_blks, vl_m4);

	      if (encrypt)
		AES_CRYPT(e, m4, LOAD_KEY, rk, rounds, data_blks, vl_m4);
	      else
		AES_CRYPT(d, m4, LOAD_KEY, rk, rounds, data_blks, vl_m4);

	      data_blks = __riscv_vxor_vv_u32m4(tweaks_m4, data_blks, vl_m4);

	      unaligned_store_u32m4(outbuf, data_blks, vl_m4);

	      tweaks_m4 = xts_gfmul_pow_m4(tweaks_m4, even_m4, max_blocks_m4,
					   vl_m4);

	      inbuf += max_blocks_m4 * BLOCKSIZE;
	      outbuf += max_blocks_m4 * BLOCKSIZE;
	      nblocks -= max_blocks_m4;
	    }
	  while (nblocks >= max_blocks_m4);

	  tweaks_m2 = __riscv_vget_v_u32m4_u32m2(tweaks_m4, 0);
	}

      if (nblocks)
	PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

      while (nblocks && nblocks >= max_blocks_m2)
	{
	  vuint32m2_t data_blks = unaligned_load_u32m2(inbuf, vl_m2);

	  data_blks = __riscv_vxor_vv_u32m2(tweaks_m2, data_blks, vl_m2);

	  if (encrypt)
	    AES_CRYPT(e, m2, GET_PRELOADED_KEY, rk, rounds, data_blks, vl_m2);
	  else
	    AES_CRYPT(d, m2, GET_PRELOADED_KEY, rk, rounds, data_blks, vl_m2);

	  data_blks = __riscv_vxor_vv_u32m2(tweaks_m2, data_blks, vl_m2);

	  unaligned_store_u32m2(outbuf, data_blks, vl_m2);

	  tweaks_m2 = xts_gfmul_pow_m2(tweaks_m2, even_m2, max_blocks_m2,
				       vl_m2);

	  inbuf += max_blocks_m2 * BLOCKSIZE;
	  outbuf += max_blocks_m2 * BLOCKSIZE;
	  nblocks -= max_blocks_m2;
	}

      tweak = __riscv_vlmul_trunc_v_u32m2_u32m1(tweaks_m2);
    }
  else if (nblocks)
    PRELOAD_ROUND_KEYS_RK10_13 (rk, rounds);

  while (nblocks)
    {
      size_t curr_nblks = nblocks_to_nblocks_per_m1(max_blocks_m1, nblocks);
      vuint32m1_t data_blks;

      vl_m1 = curr_nblks * 4;

      data_blks = unaligned_load_u32m1(inbuf, vl_m1);

      data_blks = __riscv_vxor_vv_u32m1(tweak, data_blks, vl_m1);

      if (encrypt)
	AES_CRYPT(e, m1, GET_PRELOADED_KEY, rk, rounds, data_blks, vl_m1);
      else
	AES_CRYPT(d, m1, GET_PRELOADED_KEY, rk, rounds, data_blks, vl_m1);

      data_blks = __riscv_vxor_vv_u32m1(tweak, data_blks, vl_m1);

      unaligned_store_u32m1(outbuf, data_blks, vl_m1);

      tweak = xts_gfmul_pow_m1(tweak, even_m1, curr_nblks, vl_m1);

      inbuf += curr_nblks * BLOCKSIZE;
      outbuf += curr_nblks * BLOCKSIZE;
      nblocks -= curr_nblks;
    }

  __riscv_vse32_v_u32m1((void *)tweak_arg, tweak, blk_vl32);

  clear_vec_regs();
}

ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
_gcry_aes_riscv_zvkned_xts_crypt (void *context, unsigned char *tweak_arg,
				  void *outbuf_arg, const void *inbuf_arg,
				  size_t nblocks, int encrypt)
{
  if (encrypt)
    aes_riscv_xts_crypt(context, tweak_arg, outbuf_arg, inbuf_arg, nblocks, 1);
  else
    aes_riscv_xts_crypt(context, tweak_arg, outbuf_arg, inbuf_arg, nblocks, 0);
}

#endif /* HAVE_COMPATIBLE_CC_RISCV_VECTOR_INTRINSICS */
