/* camellia-avx2-aesni-amd64.S  -  AES-NI/AVX2 implementation of Camellia cipher
 *
 * Copyright © 2013 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

#ifdef __x86_64
#include <config.h>
#if defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) && \
    defined(ENABLE_AESNI_SUPPORT) && defined(ENABLE_AVX2_SUPPORT)

#ifdef __PIC__
#  define RIP (%rip)
#else
#  define RIP
#endif

#define CAMELLIA_TABLE_BYTE_LEN 272

/* struct CAMELLIA_context: */
#define key_bitlength 0
#define key_table 4

/* register macros */
#define CTX %rdi
#define RIO %r8

/**********************************************************************
  helper macros
 **********************************************************************/
#define filter_8bit(x, lo_t, hi_t, mask4bit, tmp0) \
	vpand x, mask4bit, tmp0; \
	vpandn x, mask4bit, x; \
	vpsrld $4, x, x; \
	\
	vpshufb tmp0, lo_t, tmp0; \
	vpshufb x, hi_t, x; \
	vpxor tmp0, x, x;

#define ymm0_x xmm0
#define ymm1_x xmm1
#define ymm2_x xmm2
#define ymm3_x xmm3
#define ymm4_x xmm4
#define ymm5_x xmm5
#define ymm6_x xmm6
#define ymm7_x xmm7
#define ymm8_x xmm8
#define ymm9_x xmm9
#define ymm10_x xmm10
#define ymm11_x xmm11
#define ymm12_x xmm12
#define ymm13_x xmm13
#define ymm14_x xmm14
#define ymm15_x xmm15

/**********************************************************************
  32-way camellia
 **********************************************************************/

/*
 * IN:
 *   x0..x7: byte-sliced AB state
 *   mem_cd: register pointer storing CD state
 *   key: index for key material
 * OUT:
 *   x0..x7: new byte-sliced CD state
 */
#define roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, t0, t1, t2, t3, t4, t5, t6, \
		  t7, mem_cd, key) \
	/* \
	 * S-function with AES subbytes \
	 */ \
	vbroadcasti128 .Linv_shift_row RIP, t4; \
	vpbroadcastd .L0f0f0f0f RIP, t7; \
	vbroadcasti128 .Lpre_tf_lo_s1 RIP, t5; \
	vbroadcasti128 .Lpre_tf_hi_s1 RIP, t6; \
	vbroadcasti128 .Lpre_tf_lo_s4 RIP, t2; \
	vbroadcasti128 .Lpre_tf_hi_s4 RIP, t3; \
	\
	/* AES inverse shift rows */ \
	vpshufb t4, x0, x0; \
	vpshufb t4, x7, x7; \
	vpshufb t4, x3, x3; \
	vpshufb t4, x6, x6; \
	vpshufb t4, x2, x2; \
	vpshufb t4, x5, x5; \
	vpshufb t4, x1, x1; \
	vpshufb t4, x4, x4; \
	\
	/* prefilter sboxes 1, 2 and 3 */ \
	/* prefilter sbox 4 */ \
	filter_8bit(x0, t5, t6, t7, t4); \
	filter_8bit(x7, t5, t6, t7, t4); \
	vextracti128 $1, x0, t0##_x; \
	vextracti128 $1, x7, t1##_x; \
	filter_8bit(x3, t2, t3, t7, t4); \
	filter_8bit(x6, t2, t3, t7, t4); \
	vextracti128 $1, x3, t3##_x; \
	vextracti128 $1, x6, t2##_x; \
	filter_8bit(x2, t5, t6, t7, t4); \
	filter_8bit(x5, t5, t6, t7, t4); \
	filter_8bit(x1, t5, t6, t7, t4); \
	filter_8bit(x4, t5, t6, t7, t4); \
	\
	vpxor t4##_x, t4##_x, t4##_x; \
	\
	/* AES subbytes + AES shift rows */ \
	vextracti128 $1, x2, t6##_x; \
	vextracti128 $1, x5, t5##_x; \
	vaesenclast t4##_x, x0##_x, x0##_x; \
	vaesenclast t4##_x, t0##_x, t0##_x; \
	vinserti128 $1, t0##_x, x0, x0; \
	vaesenclast t4##_x, x7##_x, x7##_x; \
	vaesenclast t4##_x, t1##_x, t1##_x; \
	vinserti128 $1, t1##_x, x7, x7; \
	vaesenclast t4##_x, x3##_x, x3##_x; \
	vaesenclast t4##_x, t3##_x, t3##_x; \
	vinserti128 $1, t3##_x, x3, x3; \
	vaesenclast t4##_x, x6##_x, x6##_x; \
	vaesenclast t4##_x, t2##_x, t2##_x; \
	vinserti128 $1, t2##_x, x6, x6; \
	vextracti128 $1, x1, t3##_x; \
	vextracti128 $1, x4, t2##_x; \
	vbroadcasti128 .Lpost_tf_lo_s1 RIP, t0; \
	vbroadcasti128 .Lpost_tf_hi_s1 RIP, t1; \
	vaesenclast t4##_x, x2##_x, x2##_x; \
	vaesenclast t4##_x, t6##_x, t6##_x; \
	vinserti128 $1, t6##_x, x2, x2; \
	vaesenclast t4##_x, x5##_x, x5##_x; \
	vaesenclast t4##_x, t5##_x, t5##_x; \
	vinserti128 $1, t5##_x, x5, x5; \
	vaesenclast t4##_x, x1##_x, x1##_x; \
	vaesenclast t4##_x, t3##_x, t3##_x; \
	vinserti128 $1, t3##_x, x1, x1; \
	vaesenclast t4##_x, x4##_x, x4##_x; \
	vaesenclast t4##_x, t2##_x, t2##_x; \
	vinserti128 $1, t2##_x, x4, x4; \
	\
	/* postfilter sboxes 1 and 4 */ \
	vbroadcasti128 .Lpost_tf_lo_s3 RIP, t2; \
	vbroadcasti128 .Lpost_tf_hi_s3 RIP, t3; \
	filter_8bit(x0, t0, t1, t7, t4); \
	filter_8bit(x7, t0, t1, t7, t4); \
	filter_8bit(x3, t0, t1, t7, t6); \
	filter_8bit(x6, t0, t1, t7, t6); \
	\
	/* postfilter sbox 3 */ \
	vbroadcasti128 .Lpost_tf_lo_s2 RIP, t4; \
	vbroadcasti128 .Lpost_tf_hi_s2 RIP, t5; \
	filter_8bit(x2, t2, t3, t7, t6); \
	filter_8bit(x5, t2, t3, t7, t6); \
	\
	vpbroadcastq key, t0; /* higher 64-bit duplicate ignored */ \
	\
	/* postfilter sbox 2 */ \
	filter_8bit(x1, t4, t5, t7, t2); \
	filter_8bit(x4, t4, t5, t7, t2); \
	vpxor t7, t7, t7; \
	\
	vpsrldq $1, t0, t1; \
	vpsrldq $2, t0, t2; \
	vpshufb t7, t1, t1; \
	vpsrldq $3, t0, t3; \
	\
	/* P-function */ \
	vpxor x5, x0, x0; \
	vpxor x6, x1, x1; \
	vpxor x7, x2, x2; \
	vpxor x4, x3, x3; \
	\
	vpshufb t7, t2, t2; \
	vpsrldq $4, t0, t4; \
	vpshufb t7, t3, t3; \
	vpsrldq $5, t0, t5; \
	vpshufb t7, t4, t4; \
	\
	vpxor x2, x4, x4; \
	vpxor x3, x5, x5; \
	vpxor x0, x6, x6; \
	vpxor x1, x7, x7; \
	\
	vpsrldq $6, t0, t6; \
	vpshufb t7, t5, t5; \
	vpshufb t7, t6, t6; \
	\
	vpxor x7, x0, x0; \
	vpxor x4, x1, x1; \
	vpxor x5, x2, x2; \
	vpxor x6, x3, x3; \
	\
	vpxor x3, x4, x4; \
	vpxor x0, x5, x5; \
	vpxor x1, x6, x6; \
	vpxor x2, x7, x7; /* note: high and low parts swapped */ \
	\
	/* Add key material and result to CD (x becomes new CD) */ \
	\
	vpxor t6, x1, x1; \
	vpxor 5 * 32(mem_cd), x1, x1; \
	\
	vpsrldq $7, t0, t6; \
	vpshufb t7, t0, t0; \
	vpshufb t7, t6, t7; \
	\
	vpxor t7, x0, x0; \
	vpxor 4 * 32(mem_cd), x0, x0; \
	\
	vpxor t5, x2, x2; \
	vpxor 6 * 32(mem_cd), x2, x2; \
	\
	vpxor t4, x3, x3; \
	vpxor 7 * 32(mem_cd), x3, x3; \
	\
	vpxor t3, x4, x4; \
	vpxor 0 * 32(mem_cd), x4, x4; \
	\
	vpxor t2, x5, x5; \
	vpxor 1 * 32(mem_cd), x5, x5; \
	\
	vpxor t1, x6, x6; \
	vpxor 2 * 32(mem_cd), x6, x6; \
	\
	vpxor t0, x7, x7; \
	vpxor 3 * 32(mem_cd), x7, x7;

/*
 * IN/OUT:
 *  x0..x7: byte-sliced AB state preloaded
 *  mem_ab: byte-sliced AB state in memory
 *  mem_cb: byte-sliced CD state in memory
 */
#define two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, i, dir, store_ab) \
	roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		  y6, y7, mem_cd, (key_table + (i) * 8)(CTX)); \
	\
	vmovdqa x0, 4 * 32(mem_cd); \
	vmovdqa x1, 5 * 32(mem_cd); \
	vmovdqa x2, 6 * 32(mem_cd); \
	vmovdqa x3, 7 * 32(mem_cd); \
	vmovdqa x4, 0 * 32(mem_cd); \
	vmovdqa x5, 1 * 32(mem_cd); \
	vmovdqa x6, 2 * 32(mem_cd); \
	vmovdqa x7, 3 * 32(mem_cd); \
	\
	roundsm32(x4, x5, x6, x7, x0, x1, x2, x3, y0, y1, y2, y3, y4, y5, \
		  y6, y7, mem_ab, (key_table + ((i) + (dir)) * 8)(CTX)); \
	\
	store_ab(x0, x1, x2, x3, x4, x5, x6, x7, mem_ab);

#define dummy_store(x0, x1, x2, x3, x4, x5, x6, x7, mem_ab) /* do nothing */

#define store_ab_state(x0, x1, x2, x3, x4, x5, x6, x7, mem_ab) \
	/* Store new AB state */ \
	vmovdqa x4, 4 * 32(mem_ab); \
	vmovdqa x5, 5 * 32(mem_ab); \
	vmovdqa x6, 6 * 32(mem_ab); \
	vmovdqa x7, 7 * 32(mem_ab); \
	vmovdqa x0, 0 * 32(mem_ab); \
	vmovdqa x1, 1 * 32(mem_ab); \
	vmovdqa x2, 2 * 32(mem_ab); \
	vmovdqa x3, 3 * 32(mem_ab);

#define enc_rounds32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, i) \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 2, 1, store_ab_state); \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 4, 1, store_ab_state); \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 6, 1, dummy_store);

#define dec_rounds32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, i) \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 7, -1, store_ab_state); \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 5, -1, store_ab_state); \
	two_roundsm32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd, (i) + 3, -1, dummy_store);

/*
 * IN:
 *  v0..3: byte-sliced 32-bit integers
 * OUT:
 *  v0..3: (IN <<< 1)
 */
#define rol32_1_32(v0, v1, v2, v3, t0, t1, t2, zero) \
	vpcmpgtb v0, zero, t0; \
	vpaddb v0, v0, v0; \
	vpabsb t0, t0; \
	\
	vpcmpgtb v1, zero, t1; \
	vpaddb v1, v1, v1; \
	vpabsb t1, t1; \
	\
	vpcmpgtb v2, zero, t2; \
	vpaddb v2, v2, v2; \
	vpabsb t2, t2; \
	\
	vpor t0, v1, v1; \
	\
	vpcmpgtb v3, zero, t0; \
	vpaddb v3, v3, v3; \
	vpabsb t0, t0; \
	\
	vpor t1, v2, v2; \
	vpor t2, v3, v3; \
	vpor t0, v0, v0;

/*
 * IN:
 *   r: byte-sliced AB state in memory
 *   l: byte-sliced CD state in memory
 * OUT:
 *   x0..x7: new byte-sliced CD state
 */
#define fls32(l, l0, l1, l2, l3, l4, l5, l6, l7, r, t0, t1, t2, t3, tt0, \
	      tt1, tt2, tt3, kll, klr, krl, krr) \
	/* \
	 * t0 = kll; \
	 * t0 &= ll; \
	 * lr ^= rol32(t0, 1); \
	 */ \
	vpbroadcastd kll, t0; /* only lowest 32-bit used */ \
	vpxor tt0, tt0, tt0; \
	vpshufb tt0, t0, t3; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t2; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t1; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t0; \
	\
	vpand l0, t0, t0; \
	vpand l1, t1, t1; \
	vpand l2, t2, t2; \
	vpand l3, t3, t3; \
	\
	rol32_1_32(t3, t2, t1, t0, tt1, tt2, tt3, tt0); \
	\
	vpxor l4, t0, l4; \
	vpbroadcastd krr, t0; /* only lowest 32-bit used */ \
	vmovdqa l4, 4 * 32(l); \
	vpxor l5, t1, l5; \
	vmovdqa l5, 5 * 32(l); \
	vpxor l6, t2, l6; \
	vmovdqa l6, 6 * 32(l); \
	vpxor l7, t3, l7; \
	vmovdqa l7, 7 * 32(l); \
	\
	/* \
	 * t2 = krr; \
	 * t2 |= rr; \
	 * rl ^= t2; \
	 */ \
	\
	vpshufb tt0, t0, t3; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t2; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t1; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t0; \
	\
	vpor 4 * 32(r), t0, t0; \
	vpor 5 * 32(r), t1, t1; \
	vpor 6 * 32(r), t2, t2; \
	vpor 7 * 32(r), t3, t3; \
	\
	vpxor 0 * 32(r), t0, t0; \
	vpxor 1 * 32(r), t1, t1; \
	vpxor 2 * 32(r), t2, t2; \
	vpxor 3 * 32(r), t3, t3; \
	vmovdqa t0, 0 * 32(r); \
	vpbroadcastd krl, t0; /* only lowest 32-bit used */ \
	vmovdqa t1, 1 * 32(r); \
	vmovdqa t2, 2 * 32(r); \
	vmovdqa t3, 3 * 32(r); \
	\
	/* \
	 * t2 = krl; \
	 * t2 &= rl; \
	 * rr ^= rol32(t2, 1); \
	 */ \
	vpshufb tt0, t0, t3; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t2; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t1; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t0; \
	\
	vpand 0 * 32(r), t0, t0; \
	vpand 1 * 32(r), t1, t1; \
	vpand 2 * 32(r), t2, t2; \
	vpand 3 * 32(r), t3, t3; \
	\
	rol32_1_32(t3, t2, t1, t0, tt1, tt2, tt3, tt0); \
	\
	vpxor 4 * 32(r), t0, t0; \
	vpxor 5 * 32(r), t1, t1; \
	vpxor 6 * 32(r), t2, t2; \
	vpxor 7 * 32(r), t3, t3; \
	vmovdqa t0, 4 * 32(r); \
	vpbroadcastd klr, t0; /* only lowest 32-bit used */ \
	vmovdqa t1, 5 * 32(r); \
	vmovdqa t2, 6 * 32(r); \
	vmovdqa t3, 7 * 32(r); \
	\
	/* \
	 * t0 = klr; \
	 * t0 |= lr; \
	 * ll ^= t0; \
	 */ \
	\
	vpshufb tt0, t0, t3; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t2; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t1; \
	vpsrldq $1, t0, t0; \
	vpshufb tt0, t0, t0; \
	\
	vpor l4, t0, t0; \
	vpor l5, t1, t1; \
	vpor l6, t2, t2; \
	vpor l7, t3, t3; \
	\
	vpxor l0, t0, l0; \
	vmovdqa l0, 0 * 32(l); \
	vpxor l1, t1, l1; \
	vmovdqa l1, 1 * 32(l); \
	vpxor l2, t2, l2; \
	vmovdqa l2, 2 * 32(l); \
	vpxor l3, t3, l3; \
	vmovdqa l3, 3 * 32(l);

#define transpose_4x4(x0, x1, x2, x3, t1, t2) \
	vpunpckhdq x1, x0, t2; \
	vpunpckldq x1, x0, x0; \
	\
	vpunpckldq x3, x2, t1; \
	vpunpckhdq x3, x2, x2; \
	\
	vpunpckhqdq t1, x0, x1; \
	vpunpcklqdq t1, x0, x0; \
	\
	vpunpckhqdq x2, t2, x3; \
	vpunpcklqdq x2, t2, x2;

#define byteslice_16x16b_fast(a0, b0, c0, d0, a1, b1, c1, d1, a2, b2, c2, d2, \
			      a3, b3, c3, d3, st0, st1) \
	vmovdqa d2, st0; \
	vmovdqa d3, st1; \
	transpose_4x4(a0, a1, a2, a3, d2, d3); \
	transpose_4x4(b0, b1, b2, b3, d2, d3); \
	vmovdqa st0, d2; \
	vmovdqa st1, d3; \
	\
	vmovdqa a0, st0; \
	vmovdqa a1, st1; \
	transpose_4x4(c0, c1, c2, c3, a0, a1); \
	transpose_4x4(d0, d1, d2, d3, a0, a1); \
	\
	vbroadcasti128 .Lshufb_16x16b RIP, a0; \
	vmovdqa st1, a1; \
	vpshufb a0, a2, a2; \
	vpshufb a0, a3, a3; \
	vpshufb a0, b0, b0; \
	vpshufb a0, b1, b1; \
	vpshufb a0, b2, b2; \
	vpshufb a0, b3, b3; \
	vpshufb a0, a1, a1; \
	vpshufb a0, c0, c0; \
	vpshufb a0, c1, c1; \
	vpshufb a0, c2, c2; \
	vpshufb a0, c3, c3; \
	vpshufb a0, d0, d0; \
	vpshufb a0, d1, d1; \
	vpshufb a0, d2, d2; \
	vpshufb a0, d3, d3; \
	vmovdqa d3, st1; \
	vmovdqa st0, d3; \
	vpshufb a0, d3, a0; \
	vmovdqa d2, st0; \
	\
	transpose_4x4(a0, b0, c0, d0, d2, d3); \
	transpose_4x4(a1, b1, c1, d1, d2, d3); \
	vmovdqa st0, d2; \
	vmovdqa st1, d3; \
	\
	vmovdqa b0, st0; \
	vmovdqa b1, st1; \
	transpose_4x4(a2, b2, c2, d2, b0, b1); \
	transpose_4x4(a3, b3, c3, d3, b0, b1); \
	vmovdqa st0, b0; \
	vmovdqa st1, b1; \
	/* does not adjust output bytes inside vectors */

/* load blocks to registers and apply pre-whitening */
#define inpack32_pre(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		     y6, y7, rio, key) \
	vpbroadcastq key, x0; \
	vpshufb .Lpack_bswap RIP, x0, x0; \
	\
	vpxor 0 * 32(rio), x0, y7; \
	vpxor 1 * 32(rio), x0, y6; \
	vpxor 2 * 32(rio), x0, y5; \
	vpxor 3 * 32(rio), x0, y4; \
	vpxor 4 * 32(rio), x0, y3; \
	vpxor 5 * 32(rio), x0, y2; \
	vpxor 6 * 32(rio), x0, y1; \
	vpxor 7 * 32(rio), x0, y0; \
	vpxor 8 * 32(rio), x0, x7; \
	vpxor 9 * 32(rio), x0, x6; \
	vpxor 10 * 32(rio), x0, x5; \
	vpxor 11 * 32(rio), x0, x4; \
	vpxor 12 * 32(rio), x0, x3; \
	vpxor 13 * 32(rio), x0, x2; \
	vpxor 14 * 32(rio), x0, x1; \
	vpxor 15 * 32(rio), x0, x0;

/* byteslice pre-whitened blocks and store to temporary memory */
#define inpack32_post(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		      y6, y7, mem_ab, mem_cd) \
	byteslice_16x16b_fast(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, \
			      y4, y5, y6, y7, (mem_ab), (mem_cd)); \
	\
	vmovdqa x0, 0 * 32(mem_ab); \
	vmovdqa x1, 1 * 32(mem_ab); \
	vmovdqa x2, 2 * 32(mem_ab); \
	vmovdqa x3, 3 * 32(mem_ab); \
	vmovdqa x4, 4 * 32(mem_ab); \
	vmovdqa x5, 5 * 32(mem_ab); \
	vmovdqa x6, 6 * 32(mem_ab); \
	vmovdqa x7, 7 * 32(mem_ab); \
	vmovdqa y0, 0 * 32(mem_cd); \
	vmovdqa y1, 1 * 32(mem_cd); \
	vmovdqa y2, 2 * 32(mem_cd); \
	vmovdqa y3, 3 * 32(mem_cd); \
	vmovdqa y4, 4 * 32(mem_cd); \
	vmovdqa y5, 5 * 32(mem_cd); \
	vmovdqa y6, 6 * 32(mem_cd); \
	vmovdqa y7, 7 * 32(mem_cd);

/* de-byteslice, apply post-whitening and store blocks */
#define outunpack32(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, \
		    y5, y6, y7, key, stack_tmp0, stack_tmp1) \
	byteslice_16x16b_fast(y0, y4, x0, x4, y1, y5, x1, x5, y2, y6, x2, x6, \
			      y3, y7, x3, x7, stack_tmp0, stack_tmp1); \
	\
	vmovdqa x0, stack_tmp0; \
	\
	vpbroadcastq key, x0; \
	vpshufb .Lpack_bswap RIP, x0, x0; \
	\
	vpxor x0, y7, y7; \
	vpxor x0, y6, y6; \
	vpxor x0, y5, y5; \
	vpxor x0, y4, y4; \
	vpxor x0, y3, y3; \
	vpxor x0, y2, y2; \
	vpxor x0, y1, y1; \
	vpxor x0, y0, y0; \
	vpxor x0, x7, x7; \
	vpxor x0, x6, x6; \
	vpxor x0, x5, x5; \
	vpxor x0, x4, x4; \
	vpxor x0, x3, x3; \
	vpxor x0, x2, x2; \
	vpxor x0, x1, x1; \
	vpxor stack_tmp0, x0, x0;

#define write_output(x0, x1, x2, x3, x4, x5, x6, x7, y0, y1, y2, y3, y4, y5, \
		     y6, y7, rio) \
	vmovdqu x0, 0 * 32(rio); \
	vmovdqu x1, 1 * 32(rio); \
	vmovdqu x2, 2 * 32(rio); \
	vmovdqu x3, 3 * 32(rio); \
	vmovdqu x4, 4 * 32(rio); \
	vmovdqu x5, 5 * 32(rio); \
	vmovdqu x6, 6 * 32(rio); \
	vmovdqu x7, 7 * 32(rio); \
	vmovdqu y0, 8 * 32(rio); \
	vmovdqu y1, 9 * 32(rio); \
	vmovdqu y2, 10 * 32(rio); \
	vmovdqu y3, 11 * 32(rio); \
	vmovdqu y4, 12 * 32(rio); \
	vmovdqu y5, 13 * 32(rio); \
	vmovdqu y6, 14 * 32(rio); \
	vmovdqu y7, 15 * 32(rio);

.data
.align 32

#define SHUFB_BYTES(idx) \
	0 + (idx), 4 + (idx), 8 + (idx), 12 + (idx)

.Lshufb_16x16b:
	.byte SHUFB_BYTES(0), SHUFB_BYTES(1), SHUFB_BYTES(2), SHUFB_BYTES(3)
	.byte SHUFB_BYTES(0), SHUFB_BYTES(1), SHUFB_BYTES(2), SHUFB_BYTES(3)

.Lpack_bswap:
	.long 0x00010203, 0x04050607, 0x80808080, 0x80808080
	.long 0x00010203, 0x04050607, 0x80808080, 0x80808080

/* For CTR-mode IV byteswap */
.Lbswap128_mask:
	.byte 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

/*
 * pre-SubByte transform
 *
 * pre-lookup for sbox1, sbox2, sbox3:
 *   swap_bitendianness(
 *       isom_map_camellia_to_aes(
 *           camellia_f(
 *               swap_bitendianess(in)
 *           )
 *       )
 *   )
 *
 * (note: '⊕ 0xc5' inside camellia_f())
 */
.Lpre_tf_lo_s1:
	.byte 0x45, 0xe8, 0x40, 0xed, 0x2e, 0x83, 0x2b, 0x86
	.byte 0x4b, 0xe6, 0x4e, 0xe3, 0x20, 0x8d, 0x25, 0x88
.Lpre_tf_hi_s1:
	.byte 0x00, 0x51, 0xf1, 0xa0, 0x8a, 0xdb, 0x7b, 0x2a
	.byte 0x09, 0x58, 0xf8, 0xa9, 0x83, 0xd2, 0x72, 0x23

/*
 * pre-SubByte transform
 *
 * pre-lookup for sbox4:
 *   swap_bitendianness(
 *       isom_map_camellia_to_aes(
 *           camellia_f(
 *               swap_bitendianess(in <<< 1)
 *           )
 *       )
 *   )
 *
 * (note: '⊕ 0xc5' inside camellia_f())
 */
.Lpre_tf_lo_s4:
	.byte 0x45, 0x40, 0x2e, 0x2b, 0x4b, 0x4e, 0x20, 0x25
	.byte 0x14, 0x11, 0x7f, 0x7a, 0x1a, 0x1f, 0x71, 0x74
.Lpre_tf_hi_s4:
	.byte 0x00, 0xf1, 0x8a, 0x7b, 0x09, 0xf8, 0x83, 0x72
	.byte 0xad, 0x5c, 0x27, 0xd6, 0xa4, 0x55, 0x2e, 0xdf

/*
 * post-SubByte transform
 *
 * post-lookup for sbox1, sbox4:
 *  swap_bitendianness(
 *      camellia_h(
 *          isom_map_aes_to_camellia(
 *              swap_bitendianness(
 *                  aes_inverse_affine_transform(in)
 *              )
 *          )
 *      )
 *  )
 *
 * (note: '⊕ 0x6e' inside camellia_h())
 */
.Lpost_tf_lo_s1:
	.byte 0x3c, 0xcc, 0xcf, 0x3f, 0x32, 0xc2, 0xc1, 0x31
	.byte 0xdc, 0x2c, 0x2f, 0xdf, 0xd2, 0x22, 0x21, 0xd1
.Lpost_tf_hi_s1:
	.byte 0x00, 0xf9, 0x86, 0x7f, 0xd7, 0x2e, 0x51, 0xa8
	.byte 0xa4, 0x5d, 0x22, 0xdb, 0x73, 0x8a, 0xf5, 0x0c

/*
 * post-SubByte transform
 *
 * post-lookup for sbox2:
 *  swap_bitendianness(
 *      camellia_h(
 *          isom_map_aes_to_camellia(
 *              swap_bitendianness(
 *                  aes_inverse_affine_transform(in)
 *              )
 *          )
 *      )
 *  ) <<< 1
 *
 * (note: '⊕ 0x6e' inside camellia_h())
 */
.Lpost_tf_lo_s2:
	.byte 0x78, 0x99, 0x9f, 0x7e, 0x64, 0x85, 0x83, 0x62
	.byte 0xb9, 0x58, 0x5e, 0xbf, 0xa5, 0x44, 0x42, 0xa3
.Lpost_tf_hi_s2:
	.byte 0x00, 0xf3, 0x0d, 0xfe, 0xaf, 0x5c, 0xa2, 0x51
	.byte 0x49, 0xba, 0x44, 0xb7, 0xe6, 0x15, 0xeb, 0x18

/*
 * post-SubByte transform
 *
 * post-lookup for sbox3:
 *  swap_bitendianness(
 *      camellia_h(
 *          isom_map_aes_to_camellia(
 *              swap_bitendianness(
 *                  aes_inverse_affine_transform(in)
 *              )
 *          )
 *      )
 *  ) >>> 1
 *
 * (note: '⊕ 0x6e' inside camellia_h())
 */
.Lpost_tf_lo_s3:
	.byte 0x1e, 0x66, 0xe7, 0x9f, 0x19, 0x61, 0xe0, 0x98
	.byte 0x6e, 0x16, 0x97, 0xef, 0x69, 0x11, 0x90, 0xe8
.Lpost_tf_hi_s3:
	.byte 0x00, 0xfc, 0x43, 0xbf, 0xeb, 0x17, 0xa8, 0x54
	.byte 0x52, 0xae, 0x11, 0xed, 0xb9, 0x45, 0xfa, 0x06

/* For isolating SubBytes from AESENCLAST, inverse shift row */
.Linv_shift_row:
	.byte 0x00, 0x0d, 0x0a, 0x07, 0x04, 0x01, 0x0e, 0x0b
	.byte 0x08, 0x05, 0x02, 0x0f, 0x0c, 0x09, 0x06, 0x03

.align 4
/* 4-bit mask */
.L0f0f0f0f:
	.long 0x0f0f0f0f

.text

.align 8
.type   __camellia_enc_blk32,@function;

__camellia_enc_blk32:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rax: temporary storage, 512 bytes
	 *	%ymm0..%ymm15: 32 plaintext blocks
	 * output:
	 *	%ymm0..%ymm15: 32 encrypted blocks, order swapped:
	 *       7, 8, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
	 */

	leaq 8 * 32(%rax), %rcx;

	inpack32_post(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		      %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		      %ymm15, %rax, %rcx);

	enc_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 0);

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (8) * 8) + 0)(CTX),
	      ((key_table + (8) * 8) + 4)(CTX),
	      ((key_table + (8) * 8) + 8)(CTX),
	      ((key_table + (8) * 8) + 12)(CTX));

	enc_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 8);

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (16) * 8) + 0)(CTX),
	      ((key_table + (16) * 8) + 4)(CTX),
	      ((key_table + (16) * 8) + 8)(CTX),
	      ((key_table + (16) * 8) + 12)(CTX));

	enc_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 16);

	movl $24, %r8d;
	cmpl $128, key_bitlength(CTX);
	jne .Lenc_max32;

.Lenc_done:
	/* load CD for output */
	vmovdqa 0 * 32(%rcx), %ymm8;
	vmovdqa 1 * 32(%rcx), %ymm9;
	vmovdqa 2 * 32(%rcx), %ymm10;
	vmovdqa 3 * 32(%rcx), %ymm11;
	vmovdqa 4 * 32(%rcx), %ymm12;
	vmovdqa 5 * 32(%rcx), %ymm13;
	vmovdqa 6 * 32(%rcx), %ymm14;
	vmovdqa 7 * 32(%rcx), %ymm15;

	outunpack32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		    %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		    %ymm15, (key_table)(CTX, %r8, 8), (%rax), 1 * 32(%rax));

	ret;

.align 8
.Lenc_max32:
	movl $32, %r8d;

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (24) * 8) + 0)(CTX),
	      ((key_table + (24) * 8) + 4)(CTX),
	      ((key_table + (24) * 8) + 8)(CTX),
	      ((key_table + (24) * 8) + 12)(CTX));

	enc_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 24);

	jmp .Lenc_done;
.size __camellia_enc_blk32,.-__camellia_enc_blk32;

.align 8
.type   __camellia_dec_blk32,@function;

__camellia_dec_blk32:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rax: temporary storage, 512 bytes
	 *	%r8d: 24 for 16 byte key, 32 for larger
	 *	%ymm0..%ymm15: 16 encrypted blocks
	 * output:
	 *	%ymm0..%ymm15: 16 plaintext blocks, order swapped:
	 *       7, 8, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8
	 */

	leaq 8 * 32(%rax), %rcx;

	inpack32_post(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		      %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		      %ymm15, %rax, %rcx);

	cmpl $32, %r8d;
	je .Ldec_max32;

.Ldec_max24:
	dec_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 16);

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (16) * 8) + 8)(CTX),
	      ((key_table + (16) * 8) + 12)(CTX),
	      ((key_table + (16) * 8) + 0)(CTX),
	      ((key_table + (16) * 8) + 4)(CTX));

	dec_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 8);

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (8) * 8) + 8)(CTX),
	      ((key_table + (8) * 8) + 12)(CTX),
	      ((key_table + (8) * 8) + 0)(CTX),
	      ((key_table + (8) * 8) + 4)(CTX));

	dec_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 0);

	/* load CD for output */
	vmovdqa 0 * 32(%rcx), %ymm8;
	vmovdqa 1 * 32(%rcx), %ymm9;
	vmovdqa 2 * 32(%rcx), %ymm10;
	vmovdqa 3 * 32(%rcx), %ymm11;
	vmovdqa 4 * 32(%rcx), %ymm12;
	vmovdqa 5 * 32(%rcx), %ymm13;
	vmovdqa 6 * 32(%rcx), %ymm14;
	vmovdqa 7 * 32(%rcx), %ymm15;

	outunpack32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		    %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		    %ymm15, (key_table)(CTX), (%rax), 1 * 32(%rax));

	ret;

.align 8
.Ldec_max32:
	dec_rounds32(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rax, %rcx, 24);

	fls32(%rax, %ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
	      %rcx, %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
	      %ymm15,
	      ((key_table + (24) * 8) + 8)(CTX),
	      ((key_table + (24) * 8) + 12)(CTX),
	      ((key_table + (24) * 8) + 0)(CTX),
	      ((key_table + (24) * 8) + 4)(CTX));

	jmp .Ldec_max24;
.size __camellia_dec_blk32,.-__camellia_dec_blk32;

#define inc_le128(x, minus_one, tmp) \
	vpcmpeqq minus_one, x, tmp; \
	vpsubq minus_one, x, x; \
	vpslldq $8, tmp, tmp; \
	vpsubq tmp, x, x;

.align 8
.global _gcry_camellia_aesni_avx2_ctr_enc
.type   _gcry_camellia_aesni_avx2_ctr_enc,@function;

_gcry_camellia_aesni_avx2_ctr_enc:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (32 blocks)
	 *	%rdx: src (32 blocks)
	 *	%rcx: iv (big endian, 128bit)
	 */

	vzeroupper;

	movq %rsp, %r10;
	subq $(16 * 32), %rsp;
	andq $~31, %rsp;
	movq %rsp, %rax;

	vpcmpeqd %ymm15, %ymm15, %ymm15;
	vpsrldq $8, %ymm15, %ymm15; /* ab: -1:0 ; cd: -1:0 */

	/* load IV and byteswap */
	vmovdqu (%rcx), %xmm0;
	vpshufb .Lbswap128_mask RIP, %xmm0, %xmm0;
	vmovdqa %xmm0, %xmm1;
	inc_le128(%xmm0, %xmm15, %xmm14);
	vbroadcasti128 .Lbswap128_mask RIP, %ymm14;
	vinserti128 $1, %xmm0, %ymm1, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm13;
	vmovdqa %ymm13, 15 * 32(%rax);

	/* check need for handling 64-bit overflow and carry */
	cmpq $(0xffffffffffffffff - 32), (%rcx);
	ja .Lload_ctr_carry;

	/* construct IVs */
	vpaddq %ymm15, %ymm15, %ymm15; /* ab: -2:0 ; cd: -2:0 */
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm13;
	vmovdqa %ymm13, 14 * 32(%rax);
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm13;
	vmovdqa %ymm13, 13 * 32(%rax);
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm12;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm11;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm10;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm9;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm8;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm7;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm6;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm5;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm4;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm3;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm2;
	vpsubq %ymm15, %ymm0, %ymm0;
	vpshufb %ymm14, %ymm0, %ymm1;
	vpsubq %ymm15, %ymm0, %ymm0;  /* +30 ; +31 */
	vpsubq %xmm15, %xmm0, %xmm13; /* +32 */
	vpshufb %ymm14, %ymm0, %ymm0;
	vpshufb %xmm14, %xmm13, %xmm13;
	vmovdqu %xmm13, (%rcx);

	jmp .Lload_ctr_done;

.align 4
.Lload_ctr_carry:
	/* construct IVs */
	inc_le128(%ymm0, %ymm15, %ymm13); /* ab: le1 ; cd: le2 */
	inc_le128(%ymm0, %ymm15, %ymm13); /* ab: le2 ; cd: le3 */
	vpshufb %ymm14, %ymm0, %ymm13;
	vmovdqa %ymm13, 14 * 32(%rax);
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm13;
	vmovdqa %ymm13, 13 * 32(%rax);
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm12;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm11;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm10;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm9;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm8;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm7;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm6;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm5;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm4;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm3;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm2;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vpshufb %ymm14, %ymm0, %ymm1;
	inc_le128(%ymm0, %ymm15, %ymm13);
	inc_le128(%ymm0, %ymm15, %ymm13);
	vextracti128 $1, %ymm0, %xmm13;
	vpshufb %ymm14, %ymm0, %ymm0;
	inc_le128(%xmm13, %xmm15, %xmm14);
	vpshufb .Lbswap128_mask RIP, %xmm13, %xmm13;
	vmovdqu %xmm13, (%rcx);

.align 4
.Lload_ctr_done:
	/* inpack16_pre: */
	vpbroadcastq (key_table)(CTX), %ymm15;
	vpshufb .Lpack_bswap RIP, %ymm15, %ymm15;
	vpxor %ymm0, %ymm15, %ymm0;
	vpxor %ymm1, %ymm15, %ymm1;
	vpxor %ymm2, %ymm15, %ymm2;
	vpxor %ymm3, %ymm15, %ymm3;
	vpxor %ymm4, %ymm15, %ymm4;
	vpxor %ymm5, %ymm15, %ymm5;
	vpxor %ymm6, %ymm15, %ymm6;
	vpxor %ymm7, %ymm15, %ymm7;
	vpxor %ymm8, %ymm15, %ymm8;
	vpxor %ymm9, %ymm15, %ymm9;
	vpxor %ymm10, %ymm15, %ymm10;
	vpxor %ymm11, %ymm15, %ymm11;
	vpxor %ymm12, %ymm15, %ymm12;
	vpxor 13 * 32(%rax), %ymm15, %ymm13;
	vpxor 14 * 32(%rax), %ymm15, %ymm14;
	vpxor 15 * 32(%rax), %ymm15, %ymm15;

	call __camellia_enc_blk32;

	movq %r10, %rsp;

	vpxor 0 * 32(%rdx), %ymm7, %ymm7;
	vpxor 1 * 32(%rdx), %ymm6, %ymm6;
	vpxor 2 * 32(%rdx), %ymm5, %ymm5;
	vpxor 3 * 32(%rdx), %ymm4, %ymm4;
	vpxor 4 * 32(%rdx), %ymm3, %ymm3;
	vpxor 5 * 32(%rdx), %ymm2, %ymm2;
	vpxor 6 * 32(%rdx), %ymm1, %ymm1;
	vpxor 7 * 32(%rdx), %ymm0, %ymm0;
	vpxor 8 * 32(%rdx), %ymm15, %ymm15;
	vpxor 9 * 32(%rdx), %ymm14, %ymm14;
	vpxor 10 * 32(%rdx), %ymm13, %ymm13;
	vpxor 11 * 32(%rdx), %ymm12, %ymm12;
	vpxor 12 * 32(%rdx), %ymm11, %ymm11;
	vpxor 13 * 32(%rdx), %ymm10, %ymm10;
	vpxor 14 * 32(%rdx), %ymm9, %ymm9;
	vpxor 15 * 32(%rdx), %ymm8, %ymm8;
	leaq 32 * 16(%rdx), %rdx;

	write_output(%ymm7, %ymm6, %ymm5, %ymm4, %ymm3, %ymm2, %ymm1, %ymm0,
		     %ymm15, %ymm14, %ymm13, %ymm12, %ymm11, %ymm10, %ymm9,
		     %ymm8, %rsi);

	vzeroall;

	ret;
.size _gcry_camellia_aesni_avx2_ctr_enc,.-_gcry_camellia_aesni_avx2_ctr_enc;

.align 8
.global _gcry_camellia_aesni_avx2_cbc_dec
.type   _gcry_camellia_aesni_avx2_cbc_dec,@function;

_gcry_camellia_aesni_avx2_cbc_dec:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (16 blocks)
	 *	%rdx: src (16 blocks)
	 *	%rcx: iv
	 */

	vzeroupper;

	movq %rcx, %r9;

	cmpl $128, key_bitlength(CTX);
	movl $32, %r8d;
	movl $24, %eax;
	cmovel %eax, %r8d; /* max */

	movq %rsp, %r10;
	subq $(16 * 32), %rsp;
	andq $~31, %rsp;
	movq %rsp, %rax;

	inpack32_pre(%ymm0, %ymm1, %ymm2, %ymm3, %ymm4, %ymm5, %ymm6, %ymm7,
		     %ymm8, %ymm9, %ymm10, %ymm11, %ymm12, %ymm13, %ymm14,
		     %ymm15, %rdx, (key_table)(CTX, %r8, 8));

	call __camellia_dec_blk32;

	/* XOR output with IV */
	vmovdqa %ymm8, (%rax);
	vmovdqu (%r9), %xmm8;
	vinserti128 $1, (%rdx), %ymm8, %ymm8;
	vpxor %ymm8, %ymm7, %ymm7;
	vmovdqa (%rax), %ymm8;
	vpxor (0 * 32 + 16)(%rdx), %ymm6, %ymm6;
	vpxor (1 * 32 + 16)(%rdx), %ymm5, %ymm5;
	vpxor (2 * 32 + 16)(%rdx), %ymm4, %ymm4;
	vpxor (3 * 32 + 16)(%rdx), %ymm3, %ymm3;
	vpxor (4 * 32 + 16)(%rdx), %ymm2, %ymm2;
	vpxor (5 * 32 + 16)(%rdx), %ymm1, %ymm1;
	vpxor (6 * 32 + 16)(%rdx), %ymm0, %ymm0;
	vpxor (7 * 32 + 16)(%rdx), %ymm15, %ymm15;
	vpxor (8 * 32 + 16)(%rdx), %ymm14, %ymm14;
	vpxor (9 * 32 + 16)(%rdx), %ymm13, %ymm13;
	vpxor (10 * 32 + 16)(%rdx), %ymm12, %ymm12;
	vpxor (11 * 32 + 16)(%rdx), %ymm11, %ymm11;
	vpxor (12 * 32 + 16)(%rdx), %ymm10, %ymm10;
	vpxor (13 * 32 + 16)(%rdx), %ymm9, %ymm9;
	vpxor (14 * 32 + 16)(%rdx), %ymm8, %ymm8;
	movq (15 * 32 + 16 + 0)(%rdx), %rax;
	movq (15 * 32 + 16 + 8)(%rdx), %rcx;

	movq %r10, %rsp;

	write_output(%ymm7, %ymm6, %ymm5, %ymm4, %ymm3, %ymm2, %ymm1, %ymm0,
		     %ymm15, %ymm14, %ymm13, %ymm12, %ymm11, %ymm10, %ymm9,
		     %ymm8, %rsi);

	/* store new IV */
	movq %rax, (0)(%r9);
	movq %rcx, (8)(%r9);

	vzeroall;

	ret;
.size _gcry_camellia_aesni_avx2_cbc_dec,.-_gcry_camellia_aesni_avx2_cbc_dec;

.align 8
.global _gcry_camellia_aesni_avx2_cfb_dec
.type   _gcry_camellia_aesni_avx2_cfb_dec,@function;

_gcry_camellia_aesni_avx2_cfb_dec:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (16 blocks)
	 *	%rdx: src (16 blocks)
	 *	%rcx: iv
	 */

	vzeroupper;

	movq %rsp, %r10;
	subq $(16 * 32), %rsp;
	andq $~31, %rsp;
	movq %rsp, %rax;

	/* inpack16_pre: */
	vpbroadcastq (key_table)(CTX), %ymm0;
	vpshufb .Lpack_bswap RIP, %ymm0, %ymm0;
	vmovdqu (%rcx), %xmm15;
	vinserti128 $1, (%rdx), %ymm15, %ymm15;
	vpxor %ymm15, %ymm0, %ymm15;
	vmovdqu (15 * 32 + 16)(%rdx), %xmm1;
	vmovdqu %xmm1, (%rcx); /* store new IV */
	vpxor (0 * 32 + 16)(%rdx), %ymm0, %ymm14;
	vpxor (1 * 32 + 16)(%rdx), %ymm0, %ymm13;
	vpxor (2 * 32 + 16)(%rdx), %ymm0, %ymm12;
	vpxor (3 * 32 + 16)(%rdx), %ymm0, %ymm11;
	vpxor (4 * 32 + 16)(%rdx), %ymm0, %ymm10;
	vpxor (5 * 32 + 16)(%rdx), %ymm0, %ymm9;
	vpxor (6 * 32 + 16)(%rdx), %ymm0, %ymm8;
	vpxor (7 * 32 + 16)(%rdx), %ymm0, %ymm7;
	vpxor (8 * 32 + 16)(%rdx), %ymm0, %ymm6;
	vpxor (9 * 32 + 16)(%rdx), %ymm0, %ymm5;
	vpxor (10 * 32 + 16)(%rdx), %ymm0, %ymm4;
	vpxor (11 * 32 + 16)(%rdx), %ymm0, %ymm3;
	vpxor (12 * 32 + 16)(%rdx), %ymm0, %ymm2;
	vpxor (13 * 32 + 16)(%rdx), %ymm0, %ymm1;
	vpxor (14 * 32 + 16)(%rdx), %ymm0, %ymm0;

	call __camellia_enc_blk32;

	movq %r10, %rsp;

	vpxor 0 * 32(%rdx), %ymm7, %ymm7;
	vpxor 1 * 32(%rdx), %ymm6, %ymm6;
	vpxor 2 * 32(%rdx), %ymm5, %ymm5;
	vpxor 3 * 32(%rdx), %ymm4, %ymm4;
	vpxor 4 * 32(%rdx), %ymm3, %ymm3;
	vpxor 5 * 32(%rdx), %ymm2, %ymm2;
	vpxor 6 * 32(%rdx), %ymm1, %ymm1;
	vpxor 7 * 32(%rdx), %ymm0, %ymm0;
	vpxor 8 * 32(%rdx), %ymm15, %ymm15;
	vpxor 9 * 32(%rdx), %ymm14, %ymm14;
	vpxor 10 * 32(%rdx), %ymm13, %ymm13;
	vpxor 11 * 32(%rdx), %ymm12, %ymm12;
	vpxor 12 * 32(%rdx), %ymm11, %ymm11;
	vpxor 13 * 32(%rdx), %ymm10, %ymm10;
	vpxor 14 * 32(%rdx), %ymm9, %ymm9;
	vpxor 15 * 32(%rdx), %ymm8, %ymm8;

	write_output(%ymm7, %ymm6, %ymm5, %ymm4, %ymm3, %ymm2, %ymm1, %ymm0,
		     %ymm15, %ymm14, %ymm13, %ymm12, %ymm11, %ymm10, %ymm9,
		     %ymm8, %rsi);

	vzeroall;

	ret;
.size _gcry_camellia_aesni_avx2_cfb_dec,.-_gcry_camellia_aesni_avx2_cfb_dec;

#endif /*defined(ENABLE_AESNI_SUPPORT) && defined(ENABLE_AVX2_SUPPORT)*/
#endif /*__x86_64*/
