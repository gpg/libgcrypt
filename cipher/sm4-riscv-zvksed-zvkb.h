/* sm4-riscv-zvksed-zvkb.h - RISC-V vector crypto SM4 LMUL template
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

/* Included once for each LMUL with SM4_LMUL and SM4_MASK64_T set.  */

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)

#define FN(name) CAT(name##_, SM4_LMUL)
#define V32(name) CAT(__riscv_##name##_u32, SM4_LMUL)
#define V64(name) CAT(__riscv_##name##_u64, SM4_LMUL)
#define V8(name) CAT(__riscv_##name##_u8, SM4_LMUL)
#define VSETVLMAX_E64() CAT(__riscv_vsetvlmax_e64, SM4_LMUL)()
#define VEC32_T CAT(CAT(vuint32, SM4_LMUL), _t)
#define VEC64_T CAT(CAT(vuint64, SM4_LMUL), _t)
#define MASK64_T SM4_MASK64_T

#define SET_IV_m1(ivs, iv) (iv)
#define SET_IV_m2(ivs, iv) __riscv_vset(ivs, 0, iv)
#define SET_IV_m4(ivs, iv) __riscv_vset(ivs, 0, iv)
#define SET_IV(ivs, iv) CAT(SET_IV_, SM4_LMUL)(ivs, iv)


static ASM_FUNC_ATTR_INLINE VEC32_T
FN(load_u32) (const byte *p, size_t vl)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  return V32(vreinterpret)(V8(vle8_v)(p, vl * 4));
#else
  return V32(vle32_v)((const void *)p, vl);
#endif
}

static ASM_FUNC_ATTR_INLINE void
FN(store_u32) (byte *p, VEC32_T v, size_t vl)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  __riscv_vse8(p, V8(vreinterpret)(v), vl * 4);
#else
  __riscv_vse32((u32 *)(void *)p, v, vl);
#endif
}

static ASM_FUNC_ATTR_INLINE MASK64_T
FN(even_mask) (void)
{
  size_t vl64 = VSETVLMAX_E64();

  return __riscv_vmseq(__riscv_vand(V64(vid_v)(vl64), 1, vl64), 0, vl64);
}

/* Returns { ctr_lo, ctr_hi + (0 << 32), ctr_lo, ctr_hi + (1 << 32),
 *           ctr_lo, ctr_hi + (2 << 32), ... }. */
static ASM_FUNC_ATTR_INLINE VEC64_T
FN(ctr_init) (MASK64_T even, u64 ctr_lo, u64 ctr_hi)
{
  size_t vl64 = VSETVLMAX_E64();
  VEC64_T c, offs;

  offs = __riscv_vsll(__riscv_vsrl(V64(vid_v)(vl64), 1, vl64), 32, vl64);
  offs = __riscv_vmerge(offs, 0, even, vl64);
  c = V64(vmv_v_x)(ctr_hi, vl64);
  c = __riscv_vmerge(c, ctr_lo, even, vl64);
  return __riscv_vadd(c, offs, vl64);
}

/* Returns { 0, nblocks << 32, 0, nblocks << 32, ... }. */
static ASM_FUNC_ATTR_INLINE VEC64_T
FN(ctr_inc) (MASK64_T even, size_t nblocks)
{
  size_t vl64 = VSETVLMAX_E64();

  return __riscv_vmerge(V64(vmv_v_x)((u64)nblocks << 32, vl64), 0, even,
			vl64);
}

static ASM_FUNC_ATTR_INLINE VEC32_T
FN(sm4_crypt) (SM4_ROUND_KEY_PARAMS, MASK64_T even, VEC32_T x, size_t vl)
{
  size_t vl64 = vl / 2;
  VEC64_T t, y;

#ifdef HAVE_BROKEN_VSM4R_VS_INTRINSIC
  asm ( "vsetvli zero,%[vl],e32," STR2(SM4_LMUL) ",ta,ma;\n\t"
	"vsm4r.vs %[x],%[rk0];\n\t"
	"vsm4r.vs %[x],%[rk1];\n\t"
	"vsm4r.vs %[x],%[rk2];\n\t"
	"vsm4r.vs %[x],%[rk3];\n\t"
	"vsm4r.vs %[x],%[rk4];\n\t"
	"vsm4r.vs %[x],%[rk5];\n\t"
	"vsm4r.vs %[x],%[rk6];\n\t"
	"vsm4r.vs %[x],%[rk7];\n\t"
	: [x] "+vr" (x)
	: [vl] "r" (vl),
	  [rk0] "vr" (rk0), [rk1] "vr" (rk1), [rk2] "vr" (rk2),
	  [rk3] "vr" (rk3), [rk4] "vr" (rk4), [rk5] "vr" (rk5),
	  [rk6] "vr" (rk6), [rk7] "vr" (rk7)
	: "vl", "vtype", "memory");
#else
  x = __riscv_vsm4r_vs(x, rk0, vl);
  x = __riscv_vsm4r_vs(x, rk1, vl);
  x = __riscv_vsm4r_vs(x, rk2, vl);
  x = __riscv_vsm4r_vs(x, rk3, vl);
  x = __riscv_vsm4r_vs(x, rk4, vl);
  x = __riscv_vsm4r_vs(x, rk5, vl);
  x = __riscv_vsm4r_vs(x, rk6, vl);
  x = __riscv_vsm4r_vs(x, rk7, vl);
#endif

  t = __riscv_vrev8(V64(vreinterpret)(x), vl64);
  y = __riscv_vslide1up(t, 0, vl64);
  y = __riscv_vslidedown_mu(even, y, t, 1, vl64);
  return V32(vreinterpret)(y);
}

static ASM_FUNC_ATTR_INLINE void
FN(sm4_ecb_blocks) (SM4_ROUND_KEY_PARAMS, MASK64_T even, byte *out,
		    const byte *in, size_t n)
{
  size_t vl = n * 4;
  VEC32_T x;

  x = __riscv_vrev8(FN(load_u32)(in, vl), vl);
  x = FN(sm4_crypt)(SM4_ROUND_KEYS, even, x, vl);
  FN(store_u32)(out, x, vl);
}

static ASM_FUNC_ATTR_INLINE void
FN(sm4_ctr_blocks) (SM4_ROUND_KEY_PARAMS, MASK64_T even, VEC64_T *ctr,
		    VEC64_T inc, byte *out, const byte *in, size_t n)
{
  size_t vl = n * 4;
  size_t vl64 = n * 2;
  VEC32_T x, d;

  d = FN(load_u32)(in, vl);
  x = V32(vreinterpret)(*ctr);
  *ctr = __riscv_vadd(*ctr, inc, vl64);

  x = FN(sm4_crypt)(SM4_ROUND_KEYS, even, x, vl);
  x = __riscv_vxor(x, d, vl);
  FN(store_u32)(out, x, vl);
}

static ASM_FUNC_ATTR_INLINE void
FN(sm4_cbc_dec_blocks) (SM4_ROUND_KEY_PARAMS, MASK64_T even, vuint32m1_t *iv,
			VEC32_T *ivs, byte *out, const byte *in, size_t n)
{
  size_t vl = n * 4;
  VEC32_T d, x;

  d = FN(load_u32)(in, vl);
  *ivs = __riscv_vslideup(SET_IV(*ivs, *iv), d, 4, vl);
  *iv = load_u32_m1(in + (n - 1) * 16, 4);

  x = __riscv_vrev8(d, vl);
  x = FN(sm4_crypt)(SM4_ROUND_KEYS, even, x, vl);
  x = __riscv_vxor(x, *ivs, vl);
  FN(store_u32)(out, x, vl);
}

static ASM_FUNC_ATTR_INLINE void
FN(sm4_cfb_dec_blocks) (SM4_ROUND_KEY_PARAMS, MASK64_T even, vuint32m1_t *iv,
			VEC32_T *ivs, byte *out, const byte *in, size_t n)
{
  size_t vl = n * 4;
  VEC32_T d, x;

  d = FN(load_u32)(in, vl);
  *ivs = __riscv_vslideup(SET_IV(*ivs, *iv), d, 4, vl);
  *iv = load_u32_m1(in + (n - 1) * 16, 4);

  x = __riscv_vrev8(*ivs, vl);
  x = FN(sm4_crypt)(SM4_ROUND_KEYS, even, x, vl);
  x = __riscv_vxor(x, d, vl);
  FN(store_u32)(out, x, vl);
}

#undef SET_IV
#undef SET_IV_m4
#undef SET_IV_m2
#undef SET_IV_m1
#undef MASK64_T
#undef VEC64_T
#undef VEC32_T
#undef VSETVLMAX_E64
#undef V8
#undef V64
#undef V32
#undef FN
#undef CAT
#undef CAT_
#undef SM4_MASK64_T
#undef SM4_LMUL
