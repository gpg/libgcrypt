/* sha512-riscv-zvknhb-zvkb.h - RISC-V vector crypto SHA-512 LMUL template
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

/* Included once for each LMUL with SHA512_LMUL and SHA512_MASK_T set.  */

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)

#define FN(name) CAT(name##_, SHA512_LMUL)
#define V(name) CAT(__riscv_##name##_u64, SHA512_LMUL)
#define V8(name) CAT(__riscv_##name##_u8, SHA512_LMUL)
#define VEC_T CAT(CAT(vuint64, SHA512_LMUL), _t)
#define MASK_T SHA512_MASK_T


#ifdef HAVE_BROKEN_VSHA2CL_INTRINSIC
static ASM_FUNC_ATTR_INLINE VEC_T
FN(asm_vsha2cl) (VEC_T vd, VEC_T vs2, VEC_T vs1, size_t vl)
{
  asm ("vsetvli zero,%3,e64," STR2(SHA512_LMUL) ",ta,ma;\n\t"
       "vsha2cl.vv %0,%1,%2;\n\t"
       : "+vr" (vd)
       : "vr" (vs2), "vr" (vs1), "r" (vl)
       : "vl", "vtype");
  return vd;
}
# define VSHA2CL FN(asm_vsha2cl)
#else
# define VSHA2CL __riscv_vsha2cl
#endif


#define LOAD_K() \
  k_tmp = k; \
  asm ("" : "+r" (k_tmp) :: "memory"); \
  v_k = V(vle64_v)(k_tmp, vl); \
  k += 4;

/* K+W for next quad-round and K for the one after that are prepared
 * between vsha2cl and vsha2ch, ahead of use.  */

/* Quad-round with message expansion (rounds 0-63) */
#define QUAD_ROUND_W_SCHED(kw, kw_next, w0, w1, w2, w3) \
  v_hgcd_work = VSHA2CL(v_hgcd_work, v_feba_work, kw, vl); \
  kw_next = __riscv_vadd(v_k, w1, vl); \
  LOAD_K(); \
  v_feba_work = __riscv_vsha2ch(v_feba_work, v_hgcd_work, kw, vl); \
  v_w_merged = __riscv_vmerge(w2, w1, merge_mask, vl); \
  w0 = __riscv_vsha2ms(w0, v_w_merged, w3, vl);

/* Quad-round without message expansion (rounds 64-75) */
#define QUAD_ROUND_NO_SCHED(kw, kw_next, w_next, load_k) \
  v_hgcd_work = VSHA2CL(v_hgcd_work, v_feba_work, kw, vl); \
  kw_next = __riscv_vadd(v_k, w_next, vl); \
  load_k; \
  v_feba_work = __riscv_vsha2ch(v_feba_work, v_hgcd_work, kw, vl);

/* Last quad-round (rounds 76-79) */
#define QUAD_ROUND_LAST(kw) \
  v_hgcd_work = VSHA2CL(v_hgcd_work, v_feba_work, kw, vl); \
  v_feba_work = __riscv_vsha2ch(v_feba_work, v_hgcd_work, kw, vl);


static ASM_FUNC_ATTR_INLINE VEC_T
FN(load_and_swap) (const byte *p, size_t vl)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  return __riscv_vrev8(V(vreinterpret)(V8(vle8_v)(p, vl * 8)), vl);
#else
  return __riscv_vrev8(V(vle64_v)((const void *)p, vl), vl);
#endif
}

static ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 unsigned int
FN(sha512_transform_zvknhb_zvkb) (u64 state[8], const byte *data,
				  size_t nblocks, const u64 k_const[80])
{
  static const u64 feba_hgcd_indices[4] = { 40, 32, 8, 0 };
  static const int feba_offset = 0;
  static const int hgcd_offset = 16 / sizeof(u64);
  size_t vl;
  VEC_T idx;
  VEC_T v_feba_work, v_feba;
  VEC_T v_hgcd_work, v_hgcd;
  VEC_T w0, w1, w2, w3;
  VEC_T v_k, v_kw0, v_kw1, v_w_merged;
  MASK_T merge_mask;
  VEC_T v_feba_hgcd_idx;

  vl = 4;
  idx = V(vid_v)(vl);
  merge_mask = __riscv_vmseq(idx, 0, vl);

  v_feba_hgcd_idx = V(vle64_v)(feba_hgcd_indices, vl);

  v_feba = V(vluxei64_v)(state + feba_offset, v_feba_hgcd_idx, vl);
  v_hgcd = V(vluxei64_v)(state + hgcd_offset, v_feba_hgcd_idx, vl);

  while (nblocks > 0)
    {
      const u64 *k = k_const;
      const u64 *k_tmp;

      v_feba_work = v_feba;
      v_hgcd_work = v_hgcd;

      w0 = FN(load_and_swap)(data + 0, vl);
      w1 = FN(load_and_swap)(data + 32, vl);
      w2 = FN(load_and_swap)(data + 64, vl);
      w3 = FN(load_and_swap)(data + 96, vl);

      LOAD_K();
      v_kw0 = __riscv_vadd(v_k, w0, vl);
      LOAD_K();

      QUAD_ROUND_W_SCHED(v_kw0, v_kw1, w0, w1, w2, w3);
      QUAD_ROUND_W_SCHED(v_kw1, v_kw0, w1, w2, w3, w0);
      QUAD_ROUND_W_SCHED(v_kw0, v_kw1, w2, w3, w0, w1);
      QUAD_ROUND_W_SCHED(v_kw1, v_kw0, w3, w0, w1, w2);
      QUAD_ROUND_W_SCHED(v_kw0, v_kw1, w0, w1, w2, w3);
      QUAD_ROUND_W_SCHED(v_kw1, v_kw0, w1, w2, w3, w0);
      QUAD_ROUND_W_SCHED(v_kw0, v_kw1, w2, w3, w0, w1);
      QUAD_ROUND_W_SCHED(v_kw1, v_kw0, w3, w0, w1, w2);
      QUAD_ROUND_W_SCHED(v_kw0, v_kw1, w0, w1, w2, w3);
      QUAD_ROUND_W_SCHED(v_kw1, v_kw0, w1, w2, w3, w0);
      QUAD_ROUND_W_SCHED(v_kw0, v_kw1, w2, w3, w0, w1);
      QUAD_ROUND_W_SCHED(v_kw1, v_kw0, w3, w0, w1, w2);
      QUAD_ROUND_W_SCHED(v_kw0, v_kw1, w0, w1, w2, w3);
      QUAD_ROUND_W_SCHED(v_kw1, v_kw0, w1, w2, w3, w0);
      QUAD_ROUND_W_SCHED(v_kw0, v_kw1, w2, w3, w0, w1);
      QUAD_ROUND_W_SCHED(v_kw1, v_kw0, w3, w0, w1, w2);

      QUAD_ROUND_NO_SCHED(v_kw0, v_kw1, w1, LOAD_K());
      QUAD_ROUND_NO_SCHED(v_kw1, v_kw0, w2, LOAD_K());
      QUAD_ROUND_NO_SCHED(v_kw0, v_kw1, w3, (void)0);
      QUAD_ROUND_LAST(v_kw1);

      v_feba = __riscv_vadd(v_feba, v_feba_work, vl);
      v_hgcd = __riscv_vadd(v_hgcd, v_hgcd_work, vl);

      data += 128;
      nblocks--;
    }

  __riscv_vsuxei64(state + feba_offset, v_feba_hgcd_idx, v_feba, vl);
  __riscv_vsuxei64(state + hgcd_offset, v_feba_hgcd_idx, v_hgcd, vl);

  clear_vec_regs();
  return 0;
}

#undef QUAD_ROUND_LAST
#undef QUAD_ROUND_NO_SCHED
#undef QUAD_ROUND_W_SCHED
#undef LOAD_K
#undef VSHA2CL
#undef MASK_T
#undef VEC_T
#undef V8
#undef V
#undef FN
#undef CAT
#undef CAT_
#undef SHA512_MASK_T
#undef SHA512_LMUL
