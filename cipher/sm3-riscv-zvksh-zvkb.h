/* sm3-riscv-zvksh-zvkb.h - RISC-V vector crypto SM3 LMUL template
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

/* Included once for each LMUL with SM3_LMUL set.  */

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)

#define FN(name) CAT(name##_, SM3_LMUL)
#define V(name) CAT(__riscv_##name##_u32, SM3_LMUL)
#define V8(name) CAT(__riscv_##name##_u8, SM3_LMUL)
#define VEC_T CAT(CAT(vuint32, SM3_LMUL), _t)


/* Prepare vsm3c message inputs for eight rounds from W[j..j+7] in 'wa'
 * and W[j+8..j+15] in 'wb'.  vsm3c takes W[i], W[i+1] from elements 0-1
 * and W[i+4], W[i+5] from elements 4-5.  */
#define PREP_W(wa, wb, s1, s2, s3) \
  s1 = __riscv_vslidedown(wa, 2, vl); \
  s2 = __riscv_vslidedown(wa, 4, vl); \
  s2 = __riscv_vslideup(s2, wb, 4, vl); \
  s3 = __riscv_vslidedown(s2, 2, vl);

/* Eight rounds with message inputs 'wa', 's1', 's2' and 's3'.  */
#define EIGHT_ROUNDS(wa, s1, s2, s3, rnds, prep_next, expand) \
  v_hash_work = __riscv_vsm3c(v_hash_work, wa, (rnds) + 0, vl); \
  prep_next; \
  v_hash_work = __riscv_vsm3c(v_hash_work, s1, (rnds) + 1, vl); \
  expand; \
  v_hash_work = __riscv_vsm3c(v_hash_work, s2, (rnds) + 2, vl); \
  v_hash_work = __riscv_vsm3c(v_hash_work, s3, (rnds) + 3, vl);


static ASM_FUNC_ATTR_INLINE VEC_T
FN(load_msg) (const byte *p, size_t vl)
{
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  return V(vreinterpret)(V8(vle8_v)(p, vl * 4));
#else
  return V(vle32_v)((const void *)p, vl);
#endif
}

static ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 unsigned int
FN(sm3_transform_zvksh_zvkb) (u32 state[8], const byte *data, size_t nblocks)
{
  size_t vl;
  VEC_T v_hash, v_hash_work;
  VEC_T w0, w1, w2;
  VEC_T a1, a2, a3, b1, b2, b3;

  vl = 8;

  /* State is kept in big-endian byte order.  */
  v_hash = __riscv_vrev8(V(vle32_v)(state, vl), vl);

  while (nblocks > 0)
    {
      v_hash_work = v_hash;

      w0 = FN(load_msg)(data + 0, vl);
      w1 = FN(load_msg)(data + 32, vl);

      w2 = __riscv_vsm3me(w1, w0, vl);
      PREP_W(w0, w1, a1, a2, a3);

      EIGHT_ROUNDS(w0, a1, a2, a3, 0,
		   PREP_W(w1, w2, b1, b2, b3),
		   w0 = __riscv_vsm3me(w2, w1, vl));
      EIGHT_ROUNDS(w1, b1, b2, b3, 4,
		   PREP_W(w2, w0, a1, a2, a3),
		   w1 = __riscv_vsm3me(w0, w2, vl));
      EIGHT_ROUNDS(w2, a1, a2, a3, 8,
		   PREP_W(w0, w1, b1, b2, b3),
		   w2 = __riscv_vsm3me(w1, w0, vl));
      EIGHT_ROUNDS(w0, b1, b2, b3, 12,
		   PREP_W(w1, w2, a1, a2, a3),
		   w0 = __riscv_vsm3me(w2, w1, vl));
      EIGHT_ROUNDS(w1, a1, a2, a3, 16,
		   PREP_W(w2, w0, b1, b2, b3),
		   w1 = __riscv_vsm3me(w0, w2, vl));
      EIGHT_ROUNDS(w2, b1, b2, b3, 20,
		   PREP_W(w0, w1, a1, a2, a3),
		   w2 = __riscv_vsm3me(w1, w0, vl));
      EIGHT_ROUNDS(w0, a1, a2, a3, 24,
		   PREP_W(w1, w2, b1, b2, b3),
		   (void)0);
      EIGHT_ROUNDS(w1, b1, b2, b3, 28, (void)0, (void)0);

      v_hash = __riscv_vxor(v_hash, v_hash_work, vl);

      data += 64;
      nblocks--;
    }

  __riscv_vse32(state, __riscv_vrev8(v_hash, vl), vl);

  clear_vec_regs();
  return 0;
}

#undef EIGHT_ROUNDS
#undef PREP_W
#undef VEC_T
#undef V8
#undef V
#undef FN
#undef CAT
#undef CAT_
#undef SM3_LMUL
