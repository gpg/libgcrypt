/* rijndael-riscv-zvkned.c - RISC-V vector crypto implementation of AES
 * Copyright (C) 2025 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
#define cast_u8m1_u64m1(a) __riscv_vreinterpret_v_u8m1_u64m1(a)
#define cast_u32m1_u8m1(a) __riscv_vreinterpret_v_u32m1_u8m1(a)
#define cast_u32m1_u64m1(a) __riscv_vreinterpret_v_u32m1_u64m1(a)
#define cast_u64m1_u8m1(a) __riscv_vreinterpret_v_u64m1_u8m1(a)

#define cast_u8m2_u32m2(a) __riscv_vreinterpret_v_u8m2_u32m2(a)
#define cast_u32m2_u8m2(a) __riscv_vreinterpret_v_u32m2_u8m2(a)

#define cast_u8m4_u32m4(a) __riscv_vreinterpret_v_u8m4_u32m4(a)
#define cast_u32m4_u8m4(a) __riscv_vreinterpret_v_u32m4_u8m4(a)

#define cast_u64m1_u32m1(a) __riscv_vreinterpret_v_u64m1_u32m1(a)
#define cast_u32m1_u64m1(a) __riscv_vreinterpret_v_u32m1_u64m1(a)

#define cast_u64m1_i64m1(a) __riscv_vreinterpret_v_u64m1_i64m1(a)
#define cast_i64m1_u64m1(a) __riscv_vreinterpret_v_i64m1_u64m1(a)

#define memory_barrier_with_vec(a) __asm__("" : "+vr"(a) :: "memory")


static ASM_FUNC_ATTR_INLINE vuint32m1_t
bswap128_u32m1(vuint32m1_t vec, size_t vl_u32)
{
  static const byte bswap128_arr[16] =
    { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  size_t vl_bytes = vl_u32 * 4;
  vuint8m1_t bswap128 = __riscv_vle8_v_u8m1(bswap128_arr, vl_bytes);

  return cast_u8m1_u32m1(
	    __riscv_vrgather_vv_u8m1(cast_u32m1_u8m1(vec), bswap128, vl_bytes));
}

static ASM_FUNC_ATTR_INLINE vuint32m1_t
unaligned_load_u32m1(const void *ptr, size_t vl_u32)
{
  size_t vl_bytes = vl_u32 * 4;

  return cast_u8m1_u32m1(__riscv_vle8_v_u8m1(ptr, vl_bytes));
}

static ASM_FUNC_ATTR_INLINE void
unaligned_store_u32m1(void *ptr, vuint32m1_t vec, size_t vl_u32)
{
  size_t vl_bytes = vl_u32 * 4;

  __riscv_vse8_v_u8m1(ptr, cast_u32m1_u8m1(vec), vl_bytes);
}

static ASM_FUNC_ATTR_INLINE vuint32m4_t
unaligned_load_u32m4(const void *ptr, size_t vl_u32)
{
  size_t vl_bytes = vl_u32 * 4;

  return cast_u8m4_u32m4(__riscv_vle8_v_u8m4(ptr, vl_bytes));
}

static ASM_FUNC_ATTR_INLINE void
unaligned_store_u32m4(void *ptr, vuint32m4_t vec, size_t vl_u32)
{
  size_t vl_bytes = vl_u32 * 4;

  __riscv_vse8_v_u8m4(ptr, cast_u32m4_u8m4(vec), vl_bytes);
}

static vuint32m1_t
vxor_u8_u32m1(vuint32m1_t a, vuint32m1_t b, size_t vl_u32)
{
  size_t vl_bytes = vl_u32 * 4;

  return cast_u8m1_u32m1(__riscv_vxor_vv_u8m1(cast_u32m1_u8m1(a),
					      cast_u32m1_u8m1(b), vl_bytes));
}

static vuint32m4_t
vxor_u8_u32m4(vuint32m4_t a, vuint32m4_t b, size_t vl_u32)
{
  size_t vl_bytes = vl_u32 * 4;

  return cast_u8m4_u32m4(__riscv_vxor_vv_u8m4(cast_u32m4_u8m4(a),
					      cast_u32m4_u8m4(b), vl_bytes));
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
      u32 temp_array[4] = { 0, 0, 0, 0 }; \
      vuint32m1_t temp_vec; \
      temp_array[3] = (input); \
      temp_vec = __riscv_vle32_v_u32m1(temp_array, (vl)); \
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
  int rr;
  int r;

  r = 0;
  rr = rounds;
  for (r = 0, rr = rounds; r <= rounds; r++, rr--)
    {
      __riscv_vse32_v_u32m1(dkey + r * 4,
			    __riscv_vle32_v_u32m1(ekey + rr * 4, vl),
			    vl);
    }
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
  vuint32m1_t rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8; \
  vuint32m1_t rk9, rk10, rk11, rk12, rk13, rk_last;

#define PRELOAD_ROUND_KEYS(rk, nrounds, vl) \
  do { \
    rk0 = __riscv_vle32_v_u32m1(rk + 0 * 4, vl); \
    rk1 = __riscv_vle32_v_u32m1(rk + 1 * 4, vl); \
    rk2 = __riscv_vle32_v_u32m1(rk + 2 * 4, vl); \
    rk3 = __riscv_vle32_v_u32m1(rk + 3 * 4, vl); \
    rk4 = __riscv_vle32_v_u32m1(rk + 4 * 4, vl); \
    rk5 = __riscv_vle32_v_u32m1(rk + 5 * 4, vl); \
    rk6 = __riscv_vle32_v_u32m1(rk + 6 * 4, vl); \
    rk7 = __riscv_vle32_v_u32m1(rk + 7 * 4, vl); \
    rk8 = __riscv_vle32_v_u32m1(rk + 8 * 4, vl); \
    rk9 = __riscv_vle32_v_u32m1(rk + 9 * 4, vl); \
    if (UNLIKELY(nrounds >= 12)) \
      { \
        rk10 = __riscv_vle32_v_u32m1(rk + 10 * 4, vl); \
        rk11 = __riscv_vle32_v_u32m1(rk + 11 * 4, vl); \
        if (LIKELY(nrounds > 12)) \
          { \
            rk12 = __riscv_vle32_v_u32m1(rk + 12 * 4, vl); \
            rk13 = __riscv_vle32_v_u32m1(rk + 13 * 4, vl); \
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
    rk_last = __riscv_vle32_v_u32m1(rk + nrounds * 4, vl); \
  } while (0)

#ifdef HAVE_BROKEN_VAES_VS_INTRINSIC
#define AES_CRYPT(e_d, mx, nrounds, blk, vlen) \
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
	"blt %[rounds],%[num12],.Lcryptlast%=;\n\t" \
	"vaes"#e_d"m.vs %[block],%[rk10];\n\t" \
	"vaes"#e_d"m.vs %[block],%[rk11];\n\t" \
	"beq %[rounds],%[num12],.Lcryptlast%=;\n\t" \
	"vaes"#e_d"m.vs %[block],%[rk12];\n\t" \
	"vaes"#e_d"m.vs %[block],%[rk13];\n\t" \
	".Lcryptlast%=:\n\t" \
	"vaes"#e_d"f.vs %[block],%[rk_last];\n\t" \
	: [block] "+vr" (blk) \
	: [vl] "r" (vlen), [rounds] "r" (nrounds), [num12] "r" (12), \
	  [rk0] "vr" (rk0), [rk1] "vr" (rk1), [rk2] "vr" (rk2), \
	  [rk3] "vr" (rk3), [rk4] "vr" (rk4), [rk5] "vr" (rk5), \
	  [rk6] "vr" (rk6), [rk7] "vr" (rk7), [rk8] "vr" (rk8), \
	  [rk9] "vr" (rk9), [rk10] "vr" (rk10), [rk11] "vr" (rk11), \
	  [rk12] "vr" (rk12), [rk13] "vr" (rk13), \
	  [rk_last] "vr" (rk_last) \
	: "vl")
#else
#define AES_CRYPT(e_d, mx, rounds, block, vl) \
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
    if (UNLIKELY((rounds) >= 12)) \
      { \
	(block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk10, (vl)); \
	(block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk11, (vl)); \
	if (LIKELY((rounds) > 12)) \
	  { \
	    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk12, (vl)); \
	    (block) = __riscv_vaes##e_d##m_vs_u32m1_u32##mx((block), rk13, (vl)); \
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

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  block = unaligned_load_u32m1(in, vl);

  AES_CRYPT(e, m1, rounds, block, vl);

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

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  block = unaligned_load_u32m1(in, vl);

  AES_CRYPT(d, m1, rounds, block, vl);

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
  size_t vl = 4;
  ROUND_KEY_VARIABLES;

  if (!encrypt && !ctx->decryption_prepared)
    {
      do_prepare_decryption(ctx);
      ctx->decryption_prepared = 1;
    }

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  for (; nblocks >= 4; nblocks -= 4)
    {
      vuint32m4_t blocks;

      blocks = unaligned_load_u32m4(inbuf, vl * 4);

      if (encrypt)
        AES_CRYPT(e, m4, rounds, blocks, vl * 4);
      else
        AES_CRYPT(d, m4, rounds, blocks, vl * 4);

      unaligned_store_u32m4(outbuf, blocks, vl * 4);

      inbuf += 4 * BLOCKSIZE;
      outbuf += 4 * BLOCKSIZE;
    }

  for (; nblocks; nblocks--)
    {
      vuint32m1_t block;

      block = unaligned_load_u32m1(inbuf, vl);

      if (encrypt)
        AES_CRYPT(e, m1, rounds, block, vl);
      else
        AES_CRYPT(d, m1, rounds, block, vl);

      unaligned_store_u32m1(outbuf, block, vl);

      inbuf += BLOCKSIZE;
      outbuf += BLOCKSIZE;
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
  size_t vl_bytes = vl * 4;
  vuint32m1_t iv;
  ROUND_KEY_VARIABLES;

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  iv = unaligned_load_u32m1(iv_arg, vl);

  for (; nblocks; nblocks--)
    {
      vuint8m1_t data = __riscv_vle8_v_u8m1(inbuf, vl_bytes);

      AES_CRYPT(e, m1, rounds, iv, vl);

      data = __riscv_vxor_vv_u8m1(cast_u32m1_u8m1(iv), data, vl_bytes);
      __riscv_vse8_v_u8m1(outbuf, data, vl_bytes);
      iv = cast_u8m1_u32m1(data);

      outbuf += BLOCKSIZE;
      inbuf  += BLOCKSIZE;
    }

  unaligned_store_u32m1(iv_arg, iv, vl);

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
  size_t vl_bytes = vl * 4;
  vuint32m1_t iv;
  ROUND_KEY_VARIABLES;

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  iv = unaligned_load_u32m1(iv_arg, vl);

  for (; nblocks; nblocks--)
    {
      vuint8m1_t data = __riscv_vle8_v_u8m1(inbuf, vl_bytes);
      iv = cast_u8m1_u32m1(
	__riscv_vxor_vv_u8m1(data, cast_u32m1_u8m1(iv), vl_bytes));

      AES_CRYPT(e, m1, rounds, iv, vl);

      __riscv_vse8_v_u8m1(outbuf, cast_u32m1_u8m1(iv), vl_bytes);

      inbuf  += BLOCKSIZE;
      outbuf += outbuf_add;
    }

  unaligned_store_u32m1(iv_arg, iv, vl);

  clear_vec_regs();
}

ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
_gcry_aes_riscv_zvkned_ctr_enc (void *context, unsigned char *ctr_arg,
				void *outbuf_arg, const void *inbuf_arg,
				size_t nblocks)
{
  static const byte add_u8_array[4][16] =
  {
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 },
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4 }
  };
  static const u64 carry_add[2] = { 1, 1 };
  static const u64 nocarry_add[2] = { 1, 0 };
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  size_t vl_bytes = vl * 4;
  u64 ctrlow;
  vuint32m1_t ctr;
  vuint8m1_t add1;
  ROUND_KEY_VARIABLES;

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  add1 = __riscv_vle8_v_u8m1(add_u8_array[0], vl_bytes);
  ctr = unaligned_load_u32m1(ctr_arg, vl);
  ctrlow = __riscv_vmv_x_s_u64m1_u64(cast_u32m1_u64m1(bswap128_u32m1(ctr, vl)));

  memory_barrier_with_vec(add1);

  if (nblocks >= 4)
    {
      vuint8m1_t add2 = __riscv_vle8_v_u8m1(add_u8_array[1], vl_bytes);
      vuint8m1_t add3 = __riscv_vle8_v_u8m1(add_u8_array[2], vl_bytes);
      vuint8m1_t add4 = __riscv_vle8_v_u8m1(add_u8_array[3], vl_bytes);

      memory_barrier_with_vec(add2);
      memory_barrier_with_vec(add3);
      memory_barrier_with_vec(add4);

      for (; nblocks >= 4; nblocks -= 4)
	{
	  vuint8m4_t data4blks;
	  vuint32m4_t ctr4blks;

	  /* detect if 8-bit carry handling is needed */
	  if (UNLIKELY(((ctrlow += 4) & 0xff) <= 3))
	    {
	      static const u64 *adders[5][4] =
	      {
		{ nocarry_add, nocarry_add, nocarry_add, carry_add },
		{ nocarry_add, nocarry_add, carry_add, nocarry_add },
		{ nocarry_add, carry_add, nocarry_add, nocarry_add },
		{ carry_add, nocarry_add, nocarry_add, nocarry_add },
		{ nocarry_add, nocarry_add, nocarry_add, nocarry_add }
	      };
	      unsigned int idx = ctrlow <= 3 ? ctrlow : 4;
	      vuint64m1_t ctr_u64;
	      vuint32m1_t ctr_u32_1;
	      vuint32m1_t ctr_u32_2;
	      vuint32m1_t ctr_u32_3;
	      vuint32m1_t ctr_u32_4;
	      vuint64m1_t add_u64;

	      /* Byte swap counter */
	      ctr_u64 = cast_u32m1_u64m1(bswap128_u32m1(ctr, vl));

	      /* Addition with carry handling */
	      add_u64 = __riscv_vle64_v_u64m1(adders[idx][0], vl / 2);
	      ctr_u64 = __riscv_vadd_vv_u64m1(ctr_u64, add_u64, vl / 2);
	      ctr_u32_1 = cast_u64m1_u32m1(ctr_u64);

	      add_u64 = __riscv_vle64_v_u64m1(adders[idx][1], vl / 2);
	      ctr_u64 = __riscv_vadd_vv_u64m1(ctr_u64, add_u64, vl / 2);
	      ctr_u32_2 = cast_u64m1_u32m1(ctr_u64);

	      add_u64 = __riscv_vle64_v_u64m1(adders[idx][2], vl / 2);
	      ctr_u64 = __riscv_vadd_vv_u64m1(ctr_u64, add_u64, vl / 2);
	      ctr_u32_3 = cast_u64m1_u32m1(ctr_u64);

	      add_u64 = __riscv_vle64_v_u64m1(adders[idx][3], vl / 2);
	      ctr_u64 = __riscv_vadd_vv_u64m1(ctr_u64, add_u64, vl / 2);
	      ctr_u32_4 = cast_u64m1_u32m1(ctr_u64);

	      /* Byte swap counters */
	      ctr_u32_1 = bswap128_u32m1(ctr_u32_1, vl);
	      ctr_u32_2 = bswap128_u32m1(ctr_u32_2, vl);
	      ctr_u32_3 = bswap128_u32m1(ctr_u32_3, vl);
	      ctr_u32_4 = bswap128_u32m1(ctr_u32_4, vl);

	      ctr4blks = __riscv_vundefined_u32m4();
	      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 0, ctr);
	      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 1, ctr_u32_1);
	      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 2, ctr_u32_2);
	      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 3, ctr_u32_3);
	      ctr = ctr_u32_4;
	    }
	  else
	    {
	      /* Fast path addition without carry handling */
	      vuint8m1_t ctr_u8 = cast_u32m1_u8m1(ctr);
	      vuint8m1_t ctr1 = __riscv_vadd_vv_u8m1(ctr_u8, add1, vl_bytes);
	      vuint8m1_t ctr2 = __riscv_vadd_vv_u8m1(ctr_u8, add2, vl_bytes);
	      vuint8m1_t ctr3 = __riscv_vadd_vv_u8m1(ctr_u8, add3, vl_bytes);
	      vuint8m4_t ctr0123_u8 = __riscv_vundefined_u8m4();

	      ctr = cast_u8m1_u32m1(__riscv_vadd_vv_u8m1(ctr_u8, add4,
							 vl_bytes));

	      ctr0123_u8 = __riscv_vset_v_u8m1_u8m4(ctr0123_u8, 0, ctr_u8);
	      ctr0123_u8 = __riscv_vset_v_u8m1_u8m4(ctr0123_u8, 1, ctr1);
	      ctr0123_u8 = __riscv_vset_v_u8m1_u8m4(ctr0123_u8, 2, ctr2);
	      ctr0123_u8 = __riscv_vset_v_u8m1_u8m4(ctr0123_u8, 3, ctr3);

	      ctr4blks = cast_u8m4_u32m4(ctr0123_u8);
	    }

	  data4blks = __riscv_vle8_v_u8m4(inbuf, vl_bytes * 4);

	  AES_CRYPT(e, m4, rounds, ctr4blks, vl * 4);

	  data4blks = __riscv_vxor_vv_u8m4(cast_u32m4_u8m4(ctr4blks), data4blks,
					   vl_bytes * 4);
	  __riscv_vse8_v_u8m4(outbuf, data4blks, vl_bytes * 4);

	  inbuf += 4 * BLOCKSIZE;
	  outbuf += 4 * BLOCKSIZE;
	}
    }

  for (; nblocks; nblocks--)
    {
      vuint32m1_t block = ctr;
      vuint8m1_t data = __riscv_vle8_v_u8m1(inbuf, vl_bytes);

      /* detect if 8-bit carry handling is needed */
      if (UNLIKELY((++ctrlow & 0xff) == 0))
	{
	  const u64 *add_arr = UNLIKELY(ctrlow == 0) ? carry_add : nocarry_add;
	  vuint64m1_t add_val = __riscv_vle64_v_u64m1(add_arr, vl / 2);

	  /* Byte swap counter */
	  ctr = bswap128_u32m1(ctr, vl);

	  /* Addition with carry handling */
	  ctr = cast_u64m1_u32m1(__riscv_vadd_vv_u64m1(cast_u32m1_u64m1(ctr),
						       add_val, vl / 2));

	  /* Byte swap counter */
	  ctr = bswap128_u32m1(ctr, vl);
	}
      else
	{
	  /* Fast path addition without carry handling */
	  ctr = cast_u8m1_u32m1(__riscv_vadd_vv_u8m1(cast_u32m1_u8m1(ctr),
						     add1, vl_bytes));
	}

      AES_CRYPT(e, m1, rounds, block, vl);

      data = __riscv_vxor_vv_u8m1(cast_u32m1_u8m1(block), data, vl_bytes);
      __riscv_vse8_v_u8m1(outbuf, data, vl_bytes);

      inbuf  += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  unaligned_store_u32m1(ctr_arg, ctr, vl);

  clear_vec_regs();
}

ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
_gcry_aes_riscv_zvkned_ctr32le_enc (void *context, unsigned char *ctr_arg,
				    void *outbuf_arg, const void *inbuf_arg,
				    size_t nblocks)
{
  static const u32 add_u32_array[4][16] =
  {
    { 1, },  { 2, }, { 3, }, { 4, }
  };
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  size_t vl_bytes = vl * 4;
  vuint32m1_t ctr;
  vuint32m1_t add1;
  ROUND_KEY_VARIABLES;

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  add1 = __riscv_vle32_v_u32m1(add_u32_array[0], vl);
  ctr = unaligned_load_u32m1(ctr_arg, vl);

  memory_barrier_with_vec(add1);

  if (nblocks >= 4)
    {
      vuint32m1_t add2 = __riscv_vle32_v_u32m1(add_u32_array[1], vl);
      vuint32m1_t add3 = __riscv_vle32_v_u32m1(add_u32_array[2], vl);
      vuint32m1_t add4 = __riscv_vle32_v_u32m1(add_u32_array[3], vl);

      memory_barrier_with_vec(add2);
      memory_barrier_with_vec(add3);
      memory_barrier_with_vec(add4);

      for (; nblocks >= 4; nblocks -= 4)
	{
	  vuint32m1_t ctr1 = __riscv_vadd_vv_u32m1(ctr, add1, vl);
	  vuint32m1_t ctr2 = __riscv_vadd_vv_u32m1(ctr, add2, vl);
	  vuint32m1_t ctr3 = __riscv_vadd_vv_u32m1(ctr, add3, vl);
	  vuint32m4_t ctr4blks = __riscv_vundefined_u32m4();
	  vuint8m4_t data4blks;

	  ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 0, ctr);
	  ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 1, ctr1);
	  ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 2, ctr2);
	  ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 3, ctr3);
	  ctr = __riscv_vadd_vv_u32m1(ctr, add4, vl);

	  data4blks = __riscv_vle8_v_u8m4(inbuf, vl_bytes * 4);

	  AES_CRYPT(e, m4, rounds, ctr4blks, vl * 4);

	  data4blks = __riscv_vxor_vv_u8m4(cast_u32m4_u8m4(ctr4blks), data4blks,
					   vl_bytes * 4);
	  __riscv_vse8_v_u8m4(outbuf, data4blks, vl_bytes * 4);

	  inbuf += 4 * BLOCKSIZE;
	  outbuf += 4 * BLOCKSIZE;
	}
    }

  for (; nblocks; nblocks--)
    {
      vuint32m1_t block = ctr;
      vuint8m1_t data = __riscv_vle8_v_u8m1(inbuf, vl_bytes);

      ctr = __riscv_vadd_vv_u32m1(ctr, add1, vl);

      AES_CRYPT(e, m1, rounds, block, vl);

      data = __riscv_vxor_vv_u8m1(cast_u32m1_u8m1(block), data, vl_bytes);
      __riscv_vse8_v_u8m1(outbuf, data, vl_bytes);

      inbuf  += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  unaligned_store_u32m1(ctr_arg, ctr, vl);

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
  size_t vl = 4;
  vuint32m1_t iv;
  ROUND_KEY_VARIABLES;

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  iv = unaligned_load_u32m1(iv_arg, vl);

  for (; nblocks >= 4; nblocks -= 4)
    {
      vuint32m4_t data4blks = unaligned_load_u32m4(inbuf, vl * 4);
      vuint32m1_t iv1 = __riscv_vget_v_u32m4_u32m1(data4blks, 0);
      vuint32m1_t iv2 = __riscv_vget_v_u32m4_u32m1(data4blks, 1);
      vuint32m1_t iv3 = __riscv_vget_v_u32m4_u32m1(data4blks, 2);
      vuint32m1_t iv4 = __riscv_vget_v_u32m4_u32m1(data4blks, 3);
      vuint32m4_t iv4blks = __riscv_vundefined_u32m4();

      iv4blks = __riscv_vset_v_u32m1_u32m4(iv4blks, 0, iv);
      iv4blks = __riscv_vset_v_u32m1_u32m4(iv4blks, 1, iv1);
      iv4blks = __riscv_vset_v_u32m1_u32m4(iv4blks, 2, iv2);
      iv4blks = __riscv_vset_v_u32m1_u32m4(iv4blks, 3, iv3);
      iv = iv4;

      AES_CRYPT(e, m4, rounds, iv4blks, vl * 4);

      data4blks = vxor_u8_u32m4(iv4blks, data4blks, vl * 4);
      unaligned_store_u32m4(outbuf, data4blks, vl * 4);

      inbuf += 4 * BLOCKSIZE;
      outbuf += 4 * BLOCKSIZE;
    }

  for (; nblocks; nblocks--)
    {
      vuint32m1_t data = unaligned_load_u32m1(inbuf, vl);
      vuint32m1_t new_iv = data;

      AES_CRYPT(e, m1, rounds, iv, vl);

      data = vxor_u8_u32m1(iv, data, vl);
      unaligned_store_u32m1(outbuf, data, vl);
      iv = new_iv;

      inbuf  += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  unaligned_store_u32m1(iv_arg, iv, vl);

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
  size_t vl = 4;
  vuint32m1_t iv;
  ROUND_KEY_VARIABLES;

  if (!ctx->decryption_prepared)
    {
      do_prepare_decryption(ctx);
      ctx->decryption_prepared = 1;
    }

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  iv = unaligned_load_u32m1(iv_arg, vl);

  for (; nblocks >= 4; nblocks -= 4)
    {
      vuint32m4_t data4blks = unaligned_load_u32m4(inbuf, vl * 4);
      vuint32m1_t iv1 = __riscv_vget_v_u32m4_u32m1(data4blks, 0);
      vuint32m1_t iv2 = __riscv_vget_v_u32m4_u32m1(data4blks, 1);
      vuint32m1_t iv3 = __riscv_vget_v_u32m4_u32m1(data4blks, 2);
      vuint32m1_t iv4 = __riscv_vget_v_u32m4_u32m1(data4blks, 3);
      vuint32m4_t iv4blks = __riscv_vundefined_u32m4();

      iv4blks = __riscv_vset_v_u32m1_u32m4(iv4blks, 0, iv);
      iv4blks = __riscv_vset_v_u32m1_u32m4(iv4blks, 1, iv1);
      iv4blks = __riscv_vset_v_u32m1_u32m4(iv4blks, 2, iv2);
      iv4blks = __riscv_vset_v_u32m1_u32m4(iv4blks, 3, iv3);

      AES_CRYPT(d, m4, rounds, data4blks, vl * 4);

      data4blks = vxor_u8_u32m4(iv4blks, data4blks, vl * 4);
      unaligned_store_u32m4(outbuf, data4blks, vl * 4);
      iv = iv4;

      inbuf += 4 * BLOCKSIZE;
      outbuf += 4 * BLOCKSIZE;
    }

  for (; nblocks; nblocks--)
    {
      vuint32m1_t data = unaligned_load_u32m1(inbuf, vl);
      vuint32m1_t new_iv = data;

      AES_CRYPT(d, m1, rounds, data, vl);

      data = vxor_u8_u32m1(iv, data, vl);
      unaligned_store_u32m1(outbuf, data, vl);
      iv = new_iv;

      inbuf  += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  unaligned_store_u32m1(iv_arg, iv, vl);

  clear_vec_regs();
}

static ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 size_t
aes_riscv_ocb_enc (gcry_cipher_hd_t c, void *outbuf_arg,
		   const void *inbuf_arg, size_t nblocks)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  u64 n = c->u_mode.ocb.data_nblocks;
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  size_t vl_bytes = vl * 4;
  vuint32m1_t iv;
  vuint32m1_t ctr;
  ROUND_KEY_VARIABLES;

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  /* Preload Offset and Checksum */
  iv = unaligned_load_u32m1(c->u_iv.iv, vl);
  ctr = unaligned_load_u32m1(c->u_ctr.ctr, vl);

  if (nblocks >= 4)
    {
      vuint32m4_t ctr4blks = __riscv_vundefined_u32m4();
      vuint32m1_t zero = __riscv_vmv_v_x_u32m1(0, vl);

      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 0, ctr);
      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 1, zero);
      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 2, zero);
      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 3, zero);

      for (; nblocks >= 4; nblocks -= 4)
	{
	  const unsigned char *l;
	  vuint8m1_t l_ntzi;
	  vuint32m4_t data4blks = unaligned_load_u32m4(inbuf, vl * 4);
	  vuint32m4_t offsets = __riscv_vundefined_u32m4();

	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  ctr4blks = vxor_u8_u32m4(ctr4blks, data4blks, vl * 4);

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 0, iv);

	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 1, iv);

	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 2, iv);

	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 3, iv);

	  data4blks = vxor_u8_u32m4(offsets, data4blks, vl * 4);

	  AES_CRYPT(e, m4, rounds, data4blks, vl * 4);

	  data4blks = vxor_u8_u32m4(offsets, data4blks, vl * 4);

	  unaligned_store_u32m4(outbuf, data4blks, vl * 4);

	  inbuf += 4 * BLOCKSIZE;
	  outbuf += 4 * BLOCKSIZE;
	}

      /* Checksum_i = Checksum_{i-1} xor P_i  */
      ctr = vxor_u8_u32m1(__riscv_vget_v_u32m4_u32m1(ctr4blks, 0),
			  __riscv_vget_v_u32m4_u32m1(ctr4blks, 1), vl);
      ctr = vxor_u8_u32m1(ctr, __riscv_vget_v_u32m4_u32m1(ctr4blks, 2), vl);
      ctr = vxor_u8_u32m1(ctr, __riscv_vget_v_u32m4_u32m1(ctr4blks, 3), vl);
    }

  for (; nblocks; nblocks--)
    {
      const unsigned char *l;
      vuint8m1_t l_ntzi;
      vuint32m1_t data;

      data = unaligned_load_u32m1(inbuf, vl);

      /* Checksum_i = Checksum_{i-1} xor P_i  */
      ctr = vxor_u8_u32m1(ctr, data, vl);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
      l = ocb_get_l(c, ++n);
      l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
      iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);

      data = vxor_u8_u32m1(data, iv, vl);

      AES_CRYPT(e, m1, rounds, data, vl);

      data = vxor_u8_u32m1(iv, data, vl);
      unaligned_store_u32m1(outbuf, data, vl);

      inbuf  += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  c->u_mode.ocb.data_nblocks = n;

  unaligned_store_u32m1(c->u_iv.iv, iv, vl);
  unaligned_store_u32m1(c->u_ctr.ctr, ctr, vl);

  clear_vec_regs();

  return 0;
}

static ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 size_t
aes_riscv_ocb_dec (gcry_cipher_hd_t c, void *outbuf_arg,
		   const void *inbuf_arg, size_t nblocks)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  u64 n = c->u_mode.ocb.data_nblocks;
  const u32 *rk = ctx->keyschdec32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  size_t vl_bytes = vl * 4;
  vuint32m1_t iv;
  vuint32m1_t ctr;
  ROUND_KEY_VARIABLES;

  if (!ctx->decryption_prepared)
    {
      do_prepare_decryption(ctx);
      ctx->decryption_prepared = 1;
    }

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  /* Preload Offset and Checksum */
  iv = unaligned_load_u32m1(c->u_iv.iv, vl);
  ctr = unaligned_load_u32m1(c->u_ctr.ctr, vl);

  if (nblocks >= 4)
    {
      vuint32m4_t ctr4blks = __riscv_vundefined_u32m4();
      vuint32m1_t zero = __riscv_vmv_v_x_u32m1(0, vl);

      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 0, ctr);
      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 1, zero);
      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 2, zero);
      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 3, zero);

      for (; nblocks >= 4; nblocks -= 4)
	{
	  const unsigned char *l;
	  vuint8m1_t l_ntzi;
	  vuint32m4_t data4blks = unaligned_load_u32m4(inbuf, vl * 4);
	  vuint32m4_t offsets = __riscv_vundefined_u32m4();

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  /* P_i = Offset_i xor ENCIPHER(K, C_i xor Offset_i)  */
	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 0, iv);

	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 1, iv);

	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 2, iv);

	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 3, iv);

	  data4blks = vxor_u8_u32m4(offsets, data4blks, vl * 4);

	  AES_CRYPT(d, m4, rounds, data4blks, vl * 4);

	  data4blks = vxor_u8_u32m4(offsets, data4blks, vl * 4);

	  unaligned_store_u32m4(outbuf, data4blks, vl * 4);

	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  ctr4blks = vxor_u8_u32m4(ctr4blks, data4blks, vl * 4);

	  inbuf += 4 * BLOCKSIZE;
	  outbuf += 4 * BLOCKSIZE;
	}

      /* Checksum_i = Checksum_{i-1} xor P_i  */
      ctr = vxor_u8_u32m1(__riscv_vget_v_u32m4_u32m1(ctr4blks, 0),
			  __riscv_vget_v_u32m4_u32m1(ctr4blks, 1), vl);
      ctr = vxor_u8_u32m1(ctr, __riscv_vget_v_u32m4_u32m1(ctr4blks, 2), vl);
      ctr = vxor_u8_u32m1(ctr, __riscv_vget_v_u32m4_u32m1(ctr4blks, 3), vl);
    }

  for (; nblocks; nblocks--)
    {
      const unsigned char *l;
      vuint8m1_t l_ntzi;
      vuint8m1_t data;
      vuint32m1_t block;

      l = ocb_get_l(c, ++n);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)  */
      l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
      data = __riscv_vle8_v_u8m1(inbuf, vl_bytes);
      iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
      data = __riscv_vxor_vv_u8m1(data, cast_u32m1_u8m1(iv), vl_bytes);
      block = cast_u8m1_u32m1(data);

      AES_CRYPT(d, m1, rounds, block, vl);

      block = vxor_u8_u32m1(iv, block, vl);
      unaligned_store_u32m1(outbuf, block, vl);

      /* Checksum_i = Checksum_{i-1} xor P_i  */
      ctr = vxor_u8_u32m1(ctr, block, vl);

      inbuf  += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  c->u_mode.ocb.data_nblocks = n;

  unaligned_store_u32m1(c->u_iv.iv, iv, vl);
  unaligned_store_u32m1(c->u_ctr.ctr, ctr, vl);

  clear_vec_regs();

  return 0;
}

size_t ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_aes_riscv_zvkned_ocb_crypt (gcry_cipher_hd_t c, void *outbuf_arg,
				  const void *inbuf_arg, size_t nblocks,
				  int encrypt)
{
  if (encrypt)
    return aes_riscv_ocb_enc(c, outbuf_arg, inbuf_arg, nblocks);
  else
    return aes_riscv_ocb_dec(c, outbuf_arg, inbuf_arg, nblocks);
}

size_t ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2
_gcry_aes_riscv_zvkned_ocb_auth (gcry_cipher_hd_t c, const void *abuf_arg,
				 size_t nblocks)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  const unsigned char *abuf = abuf_arg;
  u64 n = c->u_mode.ocb.aad_nblocks;
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  size_t vl_bytes = vl * 4;
  vuint32m1_t iv;
  vuint32m1_t ctr;
  ROUND_KEY_VARIABLES;

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  /* Preload Offset and Sum */
  iv = unaligned_load_u32m1(c->u_mode.ocb.aad_offset, vl);
  ctr = unaligned_load_u32m1(c->u_mode.ocb.aad_sum, vl);

  if (nblocks >= 4)
    {
      vuint32m4_t ctr4blks = __riscv_vundefined_u32m4();
      vuint32m1_t zero = __riscv_vmv_v_x_u32m1(0, vl);

      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 0, ctr);
      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 1, zero);
      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 2, zero);
      ctr4blks = __riscv_vset_v_u32m1_u32m4(ctr4blks, 3, zero);

      for (; nblocks >= 4; nblocks -= 4)
	{
	  const unsigned char *l;
	  vuint8m1_t l_ntzi;
	  vuint32m4_t data4blks = unaligned_load_u32m4(abuf, vl * 4);
	  vuint32m4_t offsets = __riscv_vundefined_u32m4();

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 0, iv);

	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 1, iv);

	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 2, iv);

	  l = ocb_get_l(c, ++n);
	  l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
	  iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);
	  offsets = __riscv_vset_v_u32m1_u32m4(offsets, 3, iv);

	  data4blks = vxor_u8_u32m4(offsets, data4blks, vl * 4);

	  AES_CRYPT(e, m4, rounds, data4blks, vl * 4);

	  ctr4blks = vxor_u8_u32m4(ctr4blks, data4blks, vl * 4);

	  abuf += 4 * BLOCKSIZE;
	}

      /* Checksum_i = Checksum_{i-1} xor P_i  */
      ctr = vxor_u8_u32m1(__riscv_vget_v_u32m4_u32m1(ctr4blks, 0),
			  __riscv_vget_v_u32m4_u32m1(ctr4blks, 1), vl);
      ctr = vxor_u8_u32m1(ctr, __riscv_vget_v_u32m4_u32m1(ctr4blks, 2), vl);
      ctr = vxor_u8_u32m1(ctr, __riscv_vget_v_u32m4_u32m1(ctr4blks, 3), vl);
    }

  for (; nblocks; nblocks--)
    {
      const unsigned char *l;
      vuint8m1_t l_ntzi;
      vuint32m1_t data;

      data = unaligned_load_u32m1(abuf, vl);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
      l = ocb_get_l(c, ++n);
      l_ntzi = __riscv_vle8_v_u8m1(l, vl_bytes);
      iv = vxor_u8_u32m1(iv, cast_u8m1_u32m1(l_ntzi), vl);

      data = vxor_u8_u32m1(data, iv, vl);

      AES_CRYPT(e, m1, rounds, data, vl);

      ctr = vxor_u8_u32m1(ctr, data, vl);

      abuf += BLOCKSIZE;
    }

  c->u_mode.ocb.aad_nblocks = n;

  unaligned_store_u32m1(c->u_mode.ocb.aad_offset, iv, vl);
  unaligned_store_u32m1(c->u_mode.ocb.aad_sum, ctr, vl);

  clear_vec_regs();

  return 0;
}

static const u64 xts_gfmul_const[2] = { 0x87, 0x01 };
static const u64 xts_swap64_const[2] = { 1, 0 };

static ASM_FUNC_ATTR_INLINE vuint32m1_t
xts_gfmul_byA (vuint32m1_t vec_in, vuint64m1_t xts_gfmul,
	       vuint64m1_t xts_swap64, size_t vl)
{
  vuint64m1_t in_u64 = cast_u32m1_u64m1(vec_in);
  vuint64m1_t tmp1;

  tmp1 =
    __riscv_vrgather_vv_u64m1(cast_u32m1_u64m1(vec_in), xts_swap64, vl / 2);
  tmp1 = cast_i64m1_u64m1(
    __riscv_vsra_vx_i64m1(cast_u64m1_i64m1(tmp1), 63, vl / 2));
  in_u64 = __riscv_vadd_vv_u64m1(in_u64, in_u64, vl / 2);
  tmp1 = __riscv_vand_vv_u64m1(tmp1, xts_gfmul, vl / 2);

  return cast_u64m1_u32m1(__riscv_vxor_vv_u64m1(in_u64, tmp1, vl / 2));
}

static ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
aes_riscv_xts_enc (void *context, unsigned char *tweak_arg, void *outbuf_arg,
		   const void *inbuf_arg, size_t nblocks)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = ctx->keyschenc32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  vuint32m1_t tweak;
  vuint64m1_t xts_gfmul = __riscv_vle64_v_u64m1(xts_gfmul_const, vl / 2);
  vuint64m1_t xts_swap64 = __riscv_vle64_v_u64m1(xts_swap64_const, vl / 2);
  ROUND_KEY_VARIABLES;

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  /* Preload tweak */
  tweak = unaligned_load_u32m1(tweak_arg, vl);

  memory_barrier_with_vec(xts_gfmul);
  memory_barrier_with_vec(xts_swap64);

  for (; nblocks >= 4; nblocks -= 4)
    {
      vuint32m4_t data4blks = unaligned_load_u32m4(inbuf, vl * 4);
      vuint32m4_t tweaks = __riscv_vundefined_u32m4();

      tweaks = __riscv_vset_v_u32m1_u32m4(tweaks, 0, tweak);
      tweak = xts_gfmul_byA(tweak, xts_gfmul, xts_swap64, vl);
      tweaks = __riscv_vset_v_u32m1_u32m4(tweaks, 1, tweak);
      tweak = xts_gfmul_byA(tweak, xts_gfmul, xts_swap64, vl);
      tweaks = __riscv_vset_v_u32m1_u32m4(tweaks, 2, tweak);
      tweak = xts_gfmul_byA(tweak, xts_gfmul, xts_swap64, vl);
      tweaks = __riscv_vset_v_u32m1_u32m4(tweaks, 3, tweak);
      tweak = xts_gfmul_byA(tweak, xts_gfmul, xts_swap64, vl);

      data4blks = vxor_u8_u32m4(tweaks, data4blks, vl * 4);

      AES_CRYPT(e, m4, rounds, data4blks, vl * 4);

      data4blks = vxor_u8_u32m4(tweaks, data4blks, vl * 4);

      unaligned_store_u32m4(outbuf, data4blks, vl * 4);

      inbuf += 4 * BLOCKSIZE;
      outbuf += 4 * BLOCKSIZE;
    }

  for (; nblocks; nblocks--)
    {
      vuint32m1_t data = unaligned_load_u32m1(inbuf, vl);
      vuint32m1_t tweak0 = tweak;

      data = vxor_u8_u32m1(data, tweak0, vl);
      tweak = xts_gfmul_byA(tweak, xts_gfmul, xts_swap64, vl);

      AES_CRYPT(e, m1, rounds, data, vl);

      data = vxor_u8_u32m1(data, tweak0, vl);
      unaligned_store_u32m1(outbuf, data, vl);

      inbuf  += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  unaligned_store_u32m1(tweak_arg, tweak, vl);

  clear_vec_regs();
}

static ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
aes_riscv_xts_dec (void *context, unsigned char *tweak_arg, void *outbuf_arg,
		   const void *inbuf_arg, size_t nblocks)
{
  RIJNDAEL_context *ctx = context;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  const u32 *rk = ctx->keyschdec32[0];
  int rounds = ctx->rounds;
  size_t vl = 4;
  vuint32m1_t tweak;
  vuint64m1_t xts_gfmul = __riscv_vle64_v_u64m1(xts_gfmul_const, vl / 2);
  vuint64m1_t xts_swap64 = __riscv_vle64_v_u64m1(xts_swap64_const, vl / 2);
  ROUND_KEY_VARIABLES;

  if (!ctx->decryption_prepared)
    {
      do_prepare_decryption(ctx);
      ctx->decryption_prepared = 1;
    }

  PRELOAD_ROUND_KEYS (rk, rounds, vl);

  /* Preload tweak */
  tweak = unaligned_load_u32m1(tweak_arg, vl);

  memory_barrier_with_vec(xts_gfmul);
  memory_barrier_with_vec(xts_swap64);

  for (; nblocks >= 4; nblocks -= 4)
    {
      vuint32m4_t data4blks = unaligned_load_u32m4(inbuf, vl * 4);
      vuint32m4_t tweaks = __riscv_vundefined_u32m4();

      tweaks = __riscv_vset_v_u32m1_u32m4(tweaks, 0, tweak);
      tweak = xts_gfmul_byA(tweak, xts_gfmul, xts_swap64, vl);
      tweaks = __riscv_vset_v_u32m1_u32m4(tweaks, 1, tweak);
      tweak = xts_gfmul_byA(tweak, xts_gfmul, xts_swap64, vl);
      tweaks = __riscv_vset_v_u32m1_u32m4(tweaks, 2, tweak);
      tweak = xts_gfmul_byA(tweak, xts_gfmul, xts_swap64, vl);
      tweaks = __riscv_vset_v_u32m1_u32m4(tweaks, 3, tweak);
      tweak = xts_gfmul_byA(tweak, xts_gfmul, xts_swap64, vl);

      data4blks = vxor_u8_u32m4(tweaks, data4blks, vl * 4);

      AES_CRYPT(d, m4, rounds, data4blks, vl * 4);

      data4blks = vxor_u8_u32m4(tweaks, data4blks, vl * 4);

      unaligned_store_u32m4(outbuf, data4blks, vl * 4);

      inbuf += 4 * BLOCKSIZE;
      outbuf += 4 * BLOCKSIZE;
    }

  for (; nblocks; nblocks--)
    {
      vuint32m1_t data = unaligned_load_u32m1(inbuf, vl);
      vuint32m1_t tweak0 = tweak;

      data = vxor_u8_u32m1(data, tweak0, vl);
      tweak = xts_gfmul_byA(tweak, xts_gfmul, xts_swap64, vl);

      AES_CRYPT(d, m1, rounds, data, vl);

      data = vxor_u8_u32m1(data, tweak0, vl);
      unaligned_store_u32m1(outbuf, data, vl);

      inbuf  += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  unaligned_store_u32m1(tweak_arg, tweak, vl);

  clear_vec_regs();
}

ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 void
_gcry_aes_riscv_zvkned_xts_crypt (void *context, unsigned char *tweak_arg,
				  void *outbuf_arg, const void *inbuf_arg,
				  size_t nblocks, int encrypt)
{
  if (encrypt)
    aes_riscv_xts_enc(context, tweak_arg, outbuf_arg, inbuf_arg, nblocks);
  else
    aes_riscv_xts_dec(context, tweak_arg, outbuf_arg, inbuf_arg, nblocks);
}

#endif /* HAVE_COMPATIBLE_CC_RISCV_VECTOR_INTRINSICS */
