/* sha1-riscv-zvkb.h - RISC-V vector SHA-1 LMUL template
 * Copyright (C) 2026 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * Based on sha1.c:
 *  Copyright (C) 1998, 2001, 2002, 2003, 2008 Free Software Foundation, Inc.
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

/* Included once for each variant with SHA1_LMUL and SHA1_NBLK set.  */

#define CAT_(a, b) a##b
#define CAT(a, b) CAT_(a, b)

#define FN(name) CAT(CAT(name##_, SHA1_LMUL), CAT(x, SHA1_NBLK))
#define V(name) CAT(__riscv_##name##_u32, SHA1_LMUL)
#define V8(name) CAT(__riscv_##name##_u8, SHA1_LMUL)
#define VEC_T CAT(CAT(vuint32, SHA1_LMUL), _t)

#define LAST_BLK (SHA1_NBLK - 1)

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

#define F1(x,y,z) ( z ^ ( x & ( y ^ z ) ) )
#define F2(x,y,z) ( x ^ y ^ z )
#define F3(x,y,z) ( ( x & y ) | ( z & ( x | y ) ) )
#define F4(x,y,z) ( x ^ y ^ z )

#define R(a,b,c,d,e,f,i,blk) \
  e += rol (a, 5) + f (b, c, d) + wk[(i) * SHA1_NBLK + (blk)]; \
  b = rol (b, 30)

#define UPDATE_STATE() \
  a = (h0 += a); \
  b = (h1 += b); \
  c = (h2 += c); \
  d = (h3 += d); \
  e = (h4 += e)

#define STORE_WK(i, w, k) \
  __riscv_vse32 (wk + (i) * SHA1_NBLK, __riscv_vadd (w, k, vl), vl)

#define W_00_15(i, w, k) \
  w = FN(load_w) (data + (i) * 4, vl); \
  STORE_WK (i, w, k)

#define W_16_31(i, w, wm04, wm08, wm12, wm16, k) \
  t0 = __riscv_vslidedown (wm16, 2 * SHA1_NBLK, vl); \
  t0 = __riscv_vslideup (t0, wm12, 2 * SHA1_NBLK, vl); \
  t1 = __riscv_vslidedown_tu (zero, wm04, SHA1_NBLK, vl - SHA1_NBLK); \
  t0 = __riscv_vxor (t0, wm08, vl); \
  t1 = __riscv_vxor (t1, wm16, vl); \
  t0 = __riscv_vxor (t0, t1, vl); \
  w = __riscv_vror (t0, 31, vl); \
  t1 = __riscv_vslideup (zero, t0, 3 * SHA1_NBLK, vl); \
  t1 = __riscv_vror (t1, 30, vl); \
  w = __riscv_vxor (w, t1, vl); \
  STORE_WK (i, w, k)

#define W_32_79(i, w, wm04, wm08, wm16, wm28, k) \
  t0 = __riscv_vslidedown (wm08, 2 * SHA1_NBLK, vl); \
  t0 = __riscv_vslideup (t0, wm04, 2 * SHA1_NBLK, vl); \
  w = __riscv_vxor (w, wm28, vl); \
  t0 = __riscv_vxor (t0, wm16, vl); \
  w = __riscv_vxor (w, t0, vl); \
  w = __riscv_vror (w, 30, vl); \
  STORE_WK (i, w, k)


static ASM_FUNC_ATTR_INLINE VEC_T
FN(load_w) (const byte *p, size_t vl)
{
  VEC_T w;
#if SHA1_NBLK == 1
#ifdef RVV_UNALIGNED_NOT_ALLOWED
  w = V(vreinterpret)(V8(vle8_v)(p, vl * 4));
#else
  w = V(vle32_v)((const void *)p, vl);
#endif
#else
  vuint32mf2_t x, y;
  vuint64m1_t z;

#ifdef RVV_UNALIGNED_NOT_ALLOWED
  x = __riscv_vreinterpret_u32mf2 (__riscv_vle8_v_u8mf2 (p, 16));
  y = __riscv_vreinterpret_u32mf2 (__riscv_vle8_v_u8mf2 (p + 64, 16));
#else
  x = __riscv_vle32_v_u32mf2 ((const void *)p, 4);
  y = __riscv_vle32_v_u32mf2 ((const void *)(p + 64), 4);
#endif
  z = __riscv_vwaddu_vv_u64m1 (x, y, 4);
  z = __riscv_vwmaccu_vx_u64m1 (z, 0xffffffffU, y, 4);
  w = CAT(__riscv_vlmul_trunc_u32, SHA1_LMUL) (__riscv_vreinterpret_u32m1 (z));
#endif
  return __riscv_vrev8 (w, vl);
}

static ASM_FUNC_ATTR_NOINLINE FUNC_ATTR_OPT_O2 unsigned int
FN(sha1_transform_zvkb) (u32 state[5], const byte *data, size_t nblks)
{
  const size_t vl = 4 * SHA1_NBLK;
  u32 wk[80 * SHA1_NBLK];
  u32 a, b, c, d, e;
  u32 h0, h1, h2, h3, h4;
  VEC_T w0, w1, w2, w3, w4, w5, w6, w7;
  VEC_T t0, t1, zero;

  zero = V(vmv_v_x) (0, vl);

  a = h0 = state[0];
  b = h1 = state[1];
  c = h2 = state[2];
  d = h3 = state[3];
  e = h4 = state[4];

  W_00_15 (0, w0, K1);
  W_00_15 (4, w7, K1);
  W_00_15 (8, w6, K1);
  W_00_15 (12, w5, K1);
  W_16_31 (16, w4, w5, w6, w7, w0, K1);
  W_16_31 (20, w3, w4, w5, w6, w7, K2);
  W_16_31 (24, w2, w3, w4, w5, w6, K2);
  W_16_31 (28, w1, w2, w3, w4, w5, K2);

  for (;;)
    {
      data += 64 * SHA1_NBLK;

      R (a, b, c, d, e, F1,  0, 0);
      R (e, a, b, c, d, F1,  1, 0);
      R (d, e, a, b, c, F1,  2, 0);
      R (c, d, e, a, b, F1,  3, 0);
      W_32_79 (32, w0, w1, w2, w4, w7, K2);
      R (b, c, d, e, a, F1,  4, 0);
      R (a, b, c, d, e, F1,  5, 0);
      R (e, a, b, c, d, F1,  6, 0);
      R (d, e, a, b, c, F1,  7, 0);
      W_32_79 (36, w7, w0, w1, w3, w6, K2);
      R (c, d, e, a, b, F1,  8, 0);
      R (b, c, d, e, a, F1,  9, 0);
      R (a, b, c, d, e, F1, 10, 0);
      R (e, a, b, c, d, F1, 11, 0);
      W_32_79 (40, w6, w7, w0, w2, w5, K3);
      R (d, e, a, b, c, F1, 12, 0);
      R (c, d, e, a, b, F1, 13, 0);
      R (b, c, d, e, a, F1, 14, 0);
      R (a, b, c, d, e, F1, 15, 0);
      W_32_79 (44, w5, w6, w7, w1, w4, K3);
      R (e, a, b, c, d, F1, 16, 0);
      R (d, e, a, b, c, F1, 17, 0);
      R (c, d, e, a, b, F1, 18, 0);
      R (b, c, d, e, a, F1, 19, 0);
      W_32_79 (48, w4, w5, w6, w0, w3, K3);
      R (a, b, c, d, e, F2, 20, 0);
      R (e, a, b, c, d, F2, 21, 0);
      R (d, e, a, b, c, F2, 22, 0);
      R (c, d, e, a, b, F2, 23, 0);
      W_32_79 (52, w3, w4, w5, w7, w2, K3);
      R (b, c, d, e, a, F2, 24, 0);
      R (a, b, c, d, e, F2, 25, 0);
      R (e, a, b, c, d, F2, 26, 0);
      R (d, e, a, b, c, F2, 27, 0);
      W_32_79 (56, w2, w3, w4, w6, w1, K3);
      R (c, d, e, a, b, F2, 28, 0);
      R (b, c, d, e, a, F2, 29, 0);
      R (a, b, c, d, e, F2, 30, 0);
      R (e, a, b, c, d, F2, 31, 0);
      W_32_79 (60, w1, w2, w3, w5, w0, K4);
      R (d, e, a, b, c, F2, 32, 0);
      R (c, d, e, a, b, F2, 33, 0);
      R (b, c, d, e, a, F2, 34, 0);
      R (a, b, c, d, e, F2, 35, 0);
      W_32_79 (64, w0, w1, w2, w4, w7, K4);
      R (e, a, b, c, d, F2, 36, 0);
      R (d, e, a, b, c, F2, 37, 0);
      R (c, d, e, a, b, F2, 38, 0);
      R (b, c, d, e, a, F2, 39, 0);
      W_32_79 (68, w7, w0, w1, w3, w6, K4);
      R (a, b, c, d, e, F3, 40, 0);
      R (e, a, b, c, d, F3, 41, 0);
      R (d, e, a, b, c, F3, 42, 0);
      R (c, d, e, a, b, F3, 43, 0);
      W_32_79 (72, w6, w7, w0, w2, w5, K4);
      R (b, c, d, e, a, F3, 44, 0);
      R (a, b, c, d, e, F3, 45, 0);
      R (e, a, b, c, d, F3, 46, 0);
      R (d, e, a, b, c, F3, 47, 0);
      W_32_79 (76, w5, w6, w7, w1, w4, K4);
#if SHA1_NBLK == 2
      R (c, d, e, a, b, F3, 48, 0);
      R (b, c, d, e, a, F3, 49, 0);
      R (a, b, c, d, e, F3, 50, 0);
      R (e, a, b, c, d, F3, 51, 0);
      R (d, e, a, b, c, F3, 52, 0);
      R (c, d, e, a, b, F3, 53, 0);
      R (b, c, d, e, a, F3, 54, 0);
      R (a, b, c, d, e, F3, 55, 0);
      R (e, a, b, c, d, F3, 56, 0);
      R (d, e, a, b, c, F3, 57, 0);
      R (c, d, e, a, b, F3, 58, 0);
      R (b, c, d, e, a, F3, 59, 0);
      R (a, b, c, d, e, F4, 60, 0);
      R (e, a, b, c, d, F4, 61, 0);
      R (d, e, a, b, c, F4, 62, 0);
      R (c, d, e, a, b, F4, 63, 0);
      R (b, c, d, e, a, F4, 64, 0);
      R (a, b, c, d, e, F4, 65, 0);
      R (e, a, b, c, d, F4, 66, 0);
      R (d, e, a, b, c, F4, 67, 0);
      R (c, d, e, a, b, F4, 68, 0);
      R (b, c, d, e, a, F4, 69, 0);
      R (a, b, c, d, e, F4, 70, 0);
      R (e, a, b, c, d, F4, 71, 0);
      R (d, e, a, b, c, F4, 72, 0);
      R (c, d, e, a, b, F4, 73, 0);
      R (b, c, d, e, a, F4, 74, 0);
      R (a, b, c, d, e, F4, 75, 0);
      R (e, a, b, c, d, F4, 76, 0);
      R (d, e, a, b, c, F4, 77, 0);
      R (c, d, e, a, b, F4, 78, 0);
      R (b, c, d, e, a, F4, 79, 0);
      UPDATE_STATE ();

      R (a, b, c, d, e, F1,  0, 1);
      R (e, a, b, c, d, F1,  1, 1);
      R (d, e, a, b, c, F1,  2, 1);
      R (c, d, e, a, b, F1,  3, 1);
      R (b, c, d, e, a, F1,  4, 1);
      R (a, b, c, d, e, F1,  5, 1);
      R (e, a, b, c, d, F1,  6, 1);
      R (d, e, a, b, c, F1,  7, 1);
      R (c, d, e, a, b, F1,  8, 1);
      R (b, c, d, e, a, F1,  9, 1);
      R (a, b, c, d, e, F1, 10, 1);
      R (e, a, b, c, d, F1, 11, 1);
      R (d, e, a, b, c, F1, 12, 1);
      R (c, d, e, a, b, F1, 13, 1);
      R (b, c, d, e, a, F1, 14, 1);
      R (a, b, c, d, e, F1, 15, 1);
      R (e, a, b, c, d, F1, 16, 1);
      R (d, e, a, b, c, F1, 17, 1);
      R (c, d, e, a, b, F1, 18, 1);
      R (b, c, d, e, a, F1, 19, 1);
      R (a, b, c, d, e, F2, 20, 1);
      R (e, a, b, c, d, F2, 21, 1);
      R (d, e, a, b, c, F2, 22, 1);
      R (c, d, e, a, b, F2, 23, 1);
      R (b, c, d, e, a, F2, 24, 1);
      R (a, b, c, d, e, F2, 25, 1);
      R (e, a, b, c, d, F2, 26, 1);
      R (d, e, a, b, c, F2, 27, 1);
      R (c, d, e, a, b, F2, 28, 1);
      R (b, c, d, e, a, F2, 29, 1);
      R (a, b, c, d, e, F2, 30, 1);
      R (e, a, b, c, d, F2, 31, 1);
      R (d, e, a, b, c, F2, 32, 1);
      R (c, d, e, a, b, F2, 33, 1);
      R (b, c, d, e, a, F2, 34, 1);
      R (a, b, c, d, e, F2, 35, 1);
      R (e, a, b, c, d, F2, 36, 1);
      R (d, e, a, b, c, F2, 37, 1);
      R (c, d, e, a, b, F2, 38, 1);
      R (b, c, d, e, a, F2, 39, 1);
      R (a, b, c, d, e, F3, 40, 1);
      R (e, a, b, c, d, F3, 41, 1);
      R (d, e, a, b, c, F3, 42, 1);
      R (c, d, e, a, b, F3, 43, 1);
      R (b, c, d, e, a, F3, 44, 1);
      R (a, b, c, d, e, F3, 45, 1);
      R (e, a, b, c, d, F3, 46, 1);
      R (d, e, a, b, c, F3, 47, 1);
#endif

      nblks -= SHA1_NBLK;
      if (nblks == 0)
	break;

      R (c, d, e, a, b, F3, 48, LAST_BLK);
      R (b, c, d, e, a, F3, 49, LAST_BLK);
      R (a, b, c, d, e, F3, 50, LAST_BLK);
      R (e, a, b, c, d, F3, 51, LAST_BLK);
      W_00_15 (0, w0, K1);
      R (d, e, a, b, c, F3, 52, LAST_BLK);
      R (c, d, e, a, b, F3, 53, LAST_BLK);
      R (b, c, d, e, a, F3, 54, LAST_BLK);
      R (a, b, c, d, e, F3, 55, LAST_BLK);
      W_00_15 (4, w7, K1);
      R (e, a, b, c, d, F3, 56, LAST_BLK);
      R (d, e, a, b, c, F3, 57, LAST_BLK);
      R (c, d, e, a, b, F3, 58, LAST_BLK);
      R (b, c, d, e, a, F3, 59, LAST_BLK);
      W_00_15 (8, w6, K1);
      R (a, b, c, d, e, F4, 60, LAST_BLK);
      R (e, a, b, c, d, F4, 61, LAST_BLK);
      R (d, e, a, b, c, F4, 62, LAST_BLK);
      R (c, d, e, a, b, F4, 63, LAST_BLK);
      W_00_15 (12, w5, K1);
      R (b, c, d, e, a, F4, 64, LAST_BLK);
      R (a, b, c, d, e, F4, 65, LAST_BLK);
      R (e, a, b, c, d, F4, 66, LAST_BLK);
      R (d, e, a, b, c, F4, 67, LAST_BLK);
      W_16_31 (16, w4, w5, w6, w7, w0, K1);
      R (c, d, e, a, b, F4, 68, LAST_BLK);
      R (b, c, d, e, a, F4, 69, LAST_BLK);
      R (a, b, c, d, e, F4, 70, LAST_BLK);
      R (e, a, b, c, d, F4, 71, LAST_BLK);
      W_16_31 (20, w3, w4, w5, w6, w7, K2);
      R (d, e, a, b, c, F4, 72, LAST_BLK);
      R (c, d, e, a, b, F4, 73, LAST_BLK);
      R (b, c, d, e, a, F4, 74, LAST_BLK);
      R (a, b, c, d, e, F4, 75, LAST_BLK);
      W_16_31 (24, w2, w3, w4, w5, w6, K2);
      R (e, a, b, c, d, F4, 76, LAST_BLK);
      R (d, e, a, b, c, F4, 77, LAST_BLK);
      R (c, d, e, a, b, F4, 78, LAST_BLK);
      R (b, c, d, e, a, F4, 79, LAST_BLK);
      W_16_31 (28, w1, w2, w3, w4, w5, K2);
      UPDATE_STATE ();
    }

  R (c, d, e, a, b, F3, 48, LAST_BLK);
  R (b, c, d, e, a, F3, 49, LAST_BLK);
  R (a, b, c, d, e, F3, 50, LAST_BLK);
  R (e, a, b, c, d, F3, 51, LAST_BLK);
  R (d, e, a, b, c, F3, 52, LAST_BLK);
  R (c, d, e, a, b, F3, 53, LAST_BLK);
  R (b, c, d, e, a, F3, 54, LAST_BLK);
  R (a, b, c, d, e, F3, 55, LAST_BLK);
  R (e, a, b, c, d, F3, 56, LAST_BLK);
  R (d, e, a, b, c, F3, 57, LAST_BLK);
  R (c, d, e, a, b, F3, 58, LAST_BLK);
  R (b, c, d, e, a, F3, 59, LAST_BLK);
  R (a, b, c, d, e, F4, 60, LAST_BLK);
  R (e, a, b, c, d, F4, 61, LAST_BLK);
  R (d, e, a, b, c, F4, 62, LAST_BLK);
  R (c, d, e, a, b, F4, 63, LAST_BLK);
  R (b, c, d, e, a, F4, 64, LAST_BLK);
  R (a, b, c, d, e, F4, 65, LAST_BLK);
  R (e, a, b, c, d, F4, 66, LAST_BLK);
  R (d, e, a, b, c, F4, 67, LAST_BLK);
  R (c, d, e, a, b, F4, 68, LAST_BLK);
  R (b, c, d, e, a, F4, 69, LAST_BLK);
  R (a, b, c, d, e, F4, 70, LAST_BLK);
  R (e, a, b, c, d, F4, 71, LAST_BLK);
  R (d, e, a, b, c, F4, 72, LAST_BLK);
  R (c, d, e, a, b, F4, 73, LAST_BLK);
  R (b, c, d, e, a, F4, 74, LAST_BLK);
  R (a, b, c, d, e, F4, 75, LAST_BLK);
  R (e, a, b, c, d, F4, 76, LAST_BLK);
  R (d, e, a, b, c, F4, 77, LAST_BLK);
  R (c, d, e, a, b, F4, 78, LAST_BLK);
  R (b, c, d, e, a, F4, 79, LAST_BLK);
  UPDATE_STATE ();

  state[0] = h0;
  state[1] = h1;
  state[2] = h2;
  state[3] = h3;
  state[4] = h4;

  clear_vec_regs ();

  return sizeof (wk) + 16 * sizeof (void *);
}

#undef W_32_79
#undef W_16_31
#undef W_00_15
#undef STORE_WK
#undef UPDATE_STATE
#undef R
#undef F4
#undef F3
#undef F2
#undef F1
#undef K4
#undef K3
#undef K2
#undef K1
#undef LAST_BLK
#undef VEC_T
#undef V8
#undef V
#undef FN
#undef CAT
#undef CAT_
#undef SHA1_NBLK
#undef SHA1_LMUL
