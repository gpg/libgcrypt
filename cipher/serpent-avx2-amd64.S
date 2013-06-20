/* serpent-avx2-amd64.S  -  AVX2 implementation of Serpent cipher
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
#if defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) && defined(USE_SERPENT) && \
    defined(ENABLE_AVX2_SUPPORT)

#ifdef __PIC__
#  define RIP (%rip)
#else
#  define RIP
#endif

/* struct serpent_context: */
#define ctx_keys 0

/* register macros */
#define CTX %rdi

/* vector registers */
.set RA0, %ymm0
.set RA1, %ymm1
.set RA2, %ymm2
.set RA3, %ymm3
.set RA4, %ymm4

.set RB0, %ymm5
.set RB1, %ymm6
.set RB2, %ymm7
.set RB3, %ymm8
.set RB4, %ymm9

.set RNOT, %ymm10
.set RTMP0, %ymm11
.set RTMP1, %ymm12
.set RTMP2, %ymm13
.set RTMP3, %ymm14
.set RTMP4, %ymm15

.set RNOTx, %xmm10
.set RTMP0x, %xmm11
.set RTMP1x, %xmm12
.set RTMP2x, %xmm13
.set RTMP3x, %xmm14
.set RTMP4x, %xmm15

/**********************************************************************
  helper macros
 **********************************************************************/

/* preprocessor macro for renaming vector registers using GAS macros */
#define sbox_reg_rename(r0, r1, r2, r3, r4, \
			new_r0, new_r1, new_r2, new_r3, new_r4) \
	.set rename_reg0, new_r0; \
	.set rename_reg1, new_r1; \
	.set rename_reg2, new_r2; \
	.set rename_reg3, new_r3; \
	.set rename_reg4, new_r4; \
	\
	.set r0, rename_reg0; \
	.set r1, rename_reg1; \
	.set r2, rename_reg2; \
	.set r3, rename_reg3; \
	.set r4, rename_reg4;

/* vector 32-bit rotation to left */
#define vec_rol(reg, nleft, tmp) \
	vpslld $(nleft), reg, tmp;		\
	vpsrld $(32 - (nleft)), reg, reg;	\
	vpor tmp, reg, reg;

/* vector 32-bit rotation to right */
#define vec_ror(reg, nright, tmp) \
	vec_rol(reg, 32 - nright, tmp)

/* 4x4 32-bit integer matrix transpose */
#define transpose_4x4(x0, x1, x2, x3, t1, t2, t3) \
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

/**********************************************************************
  16-way serpent
 **********************************************************************/

/*
 * These are the S-Boxes of Serpent from following research paper.
 *
 *  D. A. Osvik, “Speeding up Serpent,” in Third AES Candidate Conference,
 *   (New York, New York, USA), p. 317–329, National Institute of Standards and
 *   Technology, 2000.
 *
 * Paper is also available at: http://www.ii.uib.no/~osvik/pub/aes3.pdf
 *
 */
#define SBOX0(r0, r1, r2, r3, r4) \
	vpxor	r0, r3, r3;		vmovdqa	r1, r4;			\
	vpand	r3, r1, r1;		vpxor	r2, r4, r4;		\
	vpxor	r0, r1, r1;		vpor	r3, r0, r0;		\
	vpxor	r4, r0, r0;		vpxor	r3, r4, r4;		\
	vpxor	r2, r3, r3;		vpor	r1, r2, r2;		\
	vpxor	r4, r2, r2;		vpxor	RNOT, r4, r4;		\
	vpor	r1, r4, r4;		vpxor	r3, r1, r1;		\
	vpxor	r4, r1, r1;		vpor	r0, r3, r3;		\
	vpxor	r3, r1, r1;		vpxor	r3, r4, r4;		\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r4,r2,r0,r3);

#define SBOX0_INVERSE(r0, r1, r2, r3, r4) \
	vpxor	RNOT, r2, r2;		vmovdqa	r1, r4;			\
	vpor	r0, r1, r1;		vpxor	RNOT, r4, r4;		\
	vpxor	r2, r1, r1;		vpor	r4, r2, r2;		\
	vpxor	r3, r1, r1;		vpxor	r4, r0, r0;		\
	vpxor	r0, r2, r2;		vpand	r3, r0, r0;		\
	vpxor	r0, r4, r4;		vpor	r1, r0, r0;		\
	vpxor	r2, r0, r0;		vpxor	r4, r3, r3;		\
	vpxor	r1, r2, r2;		vpxor	r0, r3, r3;		\
	vpxor	r1, r3, r3;	\
	vpand	r3, r2, r2;	\
	vpxor	r2, r4, r4;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r0,r4,r1,r3,r2);

#define SBOX1(r0, r1, r2, r3, r4) \
	vpxor	RNOT, r0, r0;		vpxor	RNOT, r2, r2;		\
	vmovdqa	r0, r4;			vpand	r1, r0, r0;		\
	vpxor	r0, r2, r2;		vpor	r3, r0, r0;		\
	vpxor	r2, r3, r3;		vpxor	r0, r1, r1;		\
	vpxor	r4, r0, r0;		vpor	r1, r4, r4;		\
	vpxor	r3, r1, r1;		vpor	r0, r2, r2;		\
	vpand	r4, r2, r2;		vpxor	r1, r0, r0;		\
	vpand	r2, r1, r1;	\
	vpxor	r0, r1, r1;		vpand	r2, r0, r0;		\
	vpxor	r4, r0, r0;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r2,r0,r3,r1,r4);

#define SBOX1_INVERSE(r0, r1, r2, r3, r4) \
	vmovdqa	r1, r4;			vpxor	r3, r1, r1;		\
	vpand	r1, r3, r3;		vpxor	r2, r4, r4;		\
	vpxor	r0, r3, r3;		vpor	r1, r0, r0;		\
	vpxor	r3, r2, r2;		vpxor	r4, r0, r0;		\
	vpor	r2, r0, r0;		vpxor	r3, r1, r1;		\
	vpxor	r1, r0, r0;		vpor	r3, r1, r1;		\
	vpxor	r0, r1, r1;		vpxor	RNOT, r4, r4;		\
	vpxor	r1, r4, r4;		vpor	r0, r1, r1;		\
	vpxor	r0, r1, r1;	\
	vpor	r4, r1, r1;	\
	vpxor	r1, r3, r3;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r4,r0,r3,r2,r1);

#define SBOX2(r0, r1, r2, r3, r4) \
	vmovdqa	r0, r4;			vpand	r2, r0, r0;		\
	vpxor	r3, r0, r0;		vpxor	r1, r2, r2;		\
	vpxor	r0, r2, r2;		vpor	r4, r3, r3;		\
	vpxor	r1, r3, r3;		vpxor	r2, r4, r4;		\
	vmovdqa	r3, r1;			vpor	r4, r3, r3;		\
	vpxor	r0, r3, r3;		vpand	r1, r0, r0;		\
	vpxor	r0, r4, r4;		vpxor	r3, r1, r1;		\
	vpxor	r4, r1, r1;		vpxor	RNOT, r4, r4;		\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r2,r3,r1,r4,r0);

#define SBOX2_INVERSE(r0, r1, r2, r3, r4) \
	vpxor	r3, r2, r2;		vpxor	r0, r3, r3;		\
	vmovdqa	r3, r4;			vpand	r2, r3, r3;		\
	vpxor	r1, r3, r3;		vpor	r2, r1, r1;		\
	vpxor	r4, r1, r1;		vpand	r3, r4, r4;		\
	vpxor	r3, r2, r2;		vpand	r0, r4, r4;		\
	vpxor	r2, r4, r4;		vpand	r1, r2, r2;		\
	vpor	r0, r2, r2;		vpxor	RNOT, r3, r3;		\
	vpxor	r3, r2, r2;		vpxor	r3, r0, r0;		\
	vpand	r1, r0, r0;		vpxor	r4, r3, r3;		\
	vpxor	r0, r3, r3;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r4,r2,r3,r0);

#define SBOX3(r0, r1, r2, r3, r4) \
	vmovdqa	r0, r4;			vpor	r3, r0, r0;		\
	vpxor	r1, r3, r3;		vpand	r4, r1, r1;		\
	vpxor	r2, r4, r4;		vpxor	r3, r2, r2;		\
	vpand	r0, r3, r3;		vpor	r1, r4, r4;		\
	vpxor	r4, r3, r3;		vpxor	r1, r0, r0;		\
	vpand	r0, r4, r4;		vpxor	r3, r1, r1;		\
	vpxor	r2, r4, r4;		vpor	r0, r1, r1;		\
	vpxor	r2, r1, r1;		vpxor	r3, r0, r0;		\
	vmovdqa	r1, r2;			vpor	r3, r1, r1;		\
	vpxor	r0, r1, r1;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r2,r3,r4,r0);

#define SBOX3_INVERSE(r0, r1, r2, r3, r4) \
	vmovdqa	r2, r4;			vpxor	r1, r2, r2;		\
	vpxor	r2, r0, r0;		vpand	r2, r4, r4;		\
	vpxor	r0, r4, r4;		vpand	r1, r0, r0;		\
	vpxor	r3, r1, r1;		vpor	r4, r3, r3;		\
	vpxor	r3, r2, r2;		vpxor	r3, r0, r0;		\
	vpxor	r4, r1, r1;		vpand	r2, r3, r3;		\
	vpxor	r1, r3, r3;		vpxor	r0, r1, r1;		\
	vpor	r2, r1, r1;		vpxor	r3, r0, r0;		\
	vpxor	r4, r1, r1;	\
	vpxor	r1, r0, r0;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r2,r1,r3,r0,r4);

#define SBOX4(r0, r1, r2, r3, r4) \
	vpxor	r3, r1, r1;		vpxor	RNOT, r3, r3;		\
	vpxor	r3, r2, r2;		vpxor	r0, r3, r3;		\
	vmovdqa	r1, r4;			vpand	r3, r1, r1;		\
	vpxor	r2, r1, r1;		vpxor	r3, r4, r4;		\
	vpxor	r4, r0, r0;		vpand	r4, r2, r2;		\
	vpxor	r0, r2, r2;		vpand	r1, r0, r0;		\
	vpxor	r0, r3, r3;		vpor	r1, r4, r4;		\
	vpxor	r0, r4, r4;		vpor	r3, r0, r0;		\
	vpxor	r2, r0, r0;		vpand	r3, r2, r2;		\
	vpxor	RNOT, r0, r0;		vpxor	r2, r4, r4;		\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r4,r0,r3,r2);

#define SBOX4_INVERSE(r0, r1, r2, r3, r4) \
	vmovdqa	r2, r4;			vpand	r3, r2, r2;		\
	vpxor	r1, r2, r2;		vpor	r3, r1, r1;		\
	vpand	r0, r1, r1;		vpxor	r2, r4, r4;		\
	vpxor	r1, r4, r4;		vpand	r2, r1, r1;		\
	vpxor	RNOT, r0, r0;		vpxor	r4, r3, r3;		\
	vpxor	r3, r1, r1;		vpand	r0, r3, r3;		\
	vpxor	r2, r3, r3;		vpxor	r1, r0, r0;		\
	vpand	r0, r2, r2;		vpxor	r0, r3, r3;		\
	vpxor	r4, r2, r2;	\
	vpor	r3, r2, r2;		vpxor	r0, r3, r3;		\
	vpxor	r1, r2, r2;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r0,r3,r2,r4,r1);

#define SBOX5(r0, r1, r2, r3, r4) \
	vpxor	r1, r0, r0;		vpxor	r3, r1, r1;		\
	vpxor	RNOT, r3, r3;		vmovdqa	r1, r4;			\
	vpand	r0, r1, r1;		vpxor	r3, r2, r2;		\
	vpxor	r2, r1, r1;		vpor	r4, r2, r2;		\
	vpxor	r3, r4, r4;		vpand	r1, r3, r3;		\
	vpxor	r0, r3, r3;		vpxor	r1, r4, r4;		\
	vpxor	r2, r4, r4;		vpxor	r0, r2, r2;		\
	vpand	r3, r0, r0;		vpxor	RNOT, r2, r2;		\
	vpxor	r4, r0, r0;		vpor	r3, r4, r4;		\
	vpxor	r4, r2, r2;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r3,r0,r2,r4);

#define SBOX5_INVERSE(r0, r1, r2, r3, r4) \
	vpxor	RNOT, r1, r1;		vmovdqa	r3, r4;			\
	vpxor	r1, r2, r2;		vpor	r0, r3, r3;		\
	vpxor	r2, r3, r3;		vpor	r1, r2, r2;		\
	vpand	r0, r2, r2;		vpxor	r3, r4, r4;		\
	vpxor	r4, r2, r2;		vpor	r0, r4, r4;		\
	vpxor	r1, r4, r4;		vpand	r2, r1, r1;		\
	vpxor	r3, r1, r1;		vpxor	r2, r4, r4;		\
	vpand	r4, r3, r3;		vpxor	r1, r4, r4;		\
	vpxor	r4, r3, r3;		vpxor	RNOT, r4, r4;		\
	vpxor	r0, r3, r3;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r4,r3,r2,r0);

#define SBOX6(r0, r1, r2, r3, r4) \
	vpxor	RNOT, r2, r2;		vmovdqa	r3, r4;			\
	vpand	r0, r3, r3;		vpxor	r4, r0, r0;		\
	vpxor	r2, r3, r3;		vpor	r4, r2, r2;		\
	vpxor	r3, r1, r1;		vpxor	r0, r2, r2;		\
	vpor	r1, r0, r0;		vpxor	r1, r2, r2;		\
	vpxor	r0, r4, r4;		vpor	r3, r0, r0;		\
	vpxor	r2, r0, r0;		vpxor	r3, r4, r4;		\
	vpxor	r0, r4, r4;		vpxor	RNOT, r3, r3;		\
	vpand	r4, r2, r2;	\
	vpxor	r3, r2, r2;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r0,r1,r4,r2,r3);

#define SBOX6_INVERSE(r0, r1, r2, r3, r4) \
	vpxor	r2, r0, r0;		vmovdqa	r2, r4;			\
	vpand	r0, r2, r2;		vpxor	r3, r4, r4;		\
	vpxor	RNOT, r2, r2;		vpxor	r1, r3, r3;		\
	vpxor	r3, r2, r2;		vpor	r0, r4, r4;		\
	vpxor	r2, r0, r0;		vpxor	r4, r3, r3;		\
	vpxor	r1, r4, r4;		vpand	r3, r1, r1;		\
	vpxor	r0, r1, r1;		vpxor	r3, r0, r0;		\
	vpor	r2, r0, r0;		vpxor	r1, r3, r3;		\
	vpxor	r0, r4, r4;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r2,r4,r3,r0);

#define SBOX7(r0, r1, r2, r3, r4) \
	vmovdqa	r1, r4;			vpor	r2, r1, r1;		\
	vpxor	r3, r1, r1;		vpxor	r2, r4, r4;		\
	vpxor	r1, r2, r2;		vpor	r4, r3, r3;		\
	vpand	r0, r3, r3;		vpxor	r2, r4, r4;		\
	vpxor	r1, r3, r3;		vpor	r4, r1, r1;		\
	vpxor	r0, r1, r1;		vpor	r4, r0, r0;		\
	vpxor	r2, r0, r0;		vpxor	r4, r1, r1;		\
	vpxor	r1, r2, r2;		vpand	r0, r1, r1;		\
	vpxor	r4, r1, r1;		vpxor	RNOT, r2, r2;		\
	vpor	r0, r2, r2;	\
	vpxor	r2, r4, r4;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r4,r3,r1,r0,r2);

#define SBOX7_INVERSE(r0, r1, r2, r3, r4) \
	vmovdqa	r2, r4;			vpxor	r0, r2, r2;		\
	vpand	r3, r0, r0;		vpor	r3, r4, r4;		\
	vpxor	RNOT, r2, r2;		vpxor	r1, r3, r3;		\
	vpor	r0, r1, r1;		vpxor	r2, r0, r0;		\
	vpand	r4, r2, r2;		vpand	r4, r3, r3;		\
	vpxor	r2, r1, r1;		vpxor	r0, r2, r2;		\
	vpor	r2, r0, r0;		vpxor	r1, r4, r4;		\
	vpxor	r3, r0, r0;		vpxor	r4, r3, r3;		\
	vpor	r0, r4, r4;		vpxor	r2, r3, r3;		\
	vpxor	r2, r4, r4;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r3,r0,r1,r4,r2);

/* Apply SBOX number WHICH to to the block.  */
#define SBOX(which, r0, r1, r2, r3, r4) \
	SBOX##which (r0, r1, r2, r3, r4)

/* Apply inverse SBOX number WHICH to to the block.  */
#define SBOX_INVERSE(which, r0, r1, r2, r3, r4) \
	SBOX##which##_INVERSE (r0, r1, r2, r3, r4)

/* XOR round key into block state in r0,r1,r2,r3. r4 used as temporary.  */
#define BLOCK_XOR_KEY(r0, r1, r2, r3, r4, round) \
	vpbroadcastd (ctx_keys + (round) * 16 + 0 * 4)(CTX), r4; \
	vpxor r4, r0, r0; \
	vpbroadcastd (ctx_keys + (round) * 16 + 1 * 4)(CTX), r4; \
	vpxor r4, r1, r1; \
	vpbroadcastd (ctx_keys + (round) * 16 + 2 * 4)(CTX), r4; \
	vpxor r4, r2, r2; \
	vpbroadcastd (ctx_keys + (round) * 16 + 3 * 4)(CTX), r4; \
	vpxor r4, r3, r3;

/* Apply the linear transformation to BLOCK.  */
#define LINEAR_TRANSFORMATION(r0, r1, r2, r3, r4) \
	vec_rol(r0, 13, r4);	\
	vec_rol(r2, 3, r4);	\
	vpxor r0, r1, r1;	\
	vpxor r2, r1, r1;	\
	vpslld $3, r0, r4;	\
	vpxor r2, r3, r3;	\
	vpxor r4, r3, r3;	\
	vec_rol(r1, 1, r4);	\
	vec_rol(r3, 7, r4);	\
	vpxor r1, r0, r0;	\
	vpxor r3, r0, r0;	\
	vpslld $7, r1, r4;	\
	vpxor r3, r2, r2;	\
	vpxor r4, r2, r2;	\
	vec_rol(r0, 5, r4);	\
	vec_rol(r2, 22, r4);

/* Apply the inverse linear transformation to BLOCK.  */
#define LINEAR_TRANSFORMATION_INVERSE(r0, r1, r2, r3, r4) \
	vec_ror(r2, 22, r4);	\
	vec_ror(r0, 5, r4);	\
	vpslld $7, r1, r4;	\
	vpxor r3, r2, r2;	\
	vpxor r4, r2, r2;	\
	vpxor r1, r0, r0;	\
	vpxor r3, r0, r0;	\
	vec_ror(r3, 7, r4);	\
	vec_ror(r1, 1, r4);	\
	vpslld $3, r0, r4;	\
	vpxor r2, r3, r3;	\
	vpxor r4, r3, r3;	\
	vpxor r0, r1, r1;	\
	vpxor r2, r1, r1;	\
	vec_ror(r2, 3, r4);	\
	vec_ror(r0, 13, r4);

/* Apply a Serpent round to sixteen parallel blocks.  This macro increments
   `round'.  */
#define ROUND(which, a0, a1, a2, a3, a4, b0, b1, b2, b3, b4) \
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, round);	\
	SBOX (which, a0, a1, a2, a3, a4);		\
		BLOCK_XOR_KEY (b0, b1, b2, b3, b4, round);	\
		SBOX (which, b0, b1, b2, b3, b4);		\
	LINEAR_TRANSFORMATION (a0, a1, a2, a3, a4);	\
		LINEAR_TRANSFORMATION (b0, b1, b2, b3, b4);	\
	.set round, (round + 1);

/* Apply the last Serpent round to sixteen parallel blocks.  This macro
   increments `round'.  */
#define ROUND_LAST(which, a0, a1, a2, a3, a4, b0, b1, b2, b3, b4) \
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, round);	\
	SBOX (which, a0, a1, a2, a3, a4);		\
		BLOCK_XOR_KEY (b0, b1, b2, b3, b4, round);	\
		SBOX (which, b0, b1, b2, b3, b4);		\
	.set round, (round + 1);			\
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, round);	\
		BLOCK_XOR_KEY (b0, b1, b2, b3, b4, round);	\
	.set round, (round + 1);

/* Apply an inverse Serpent round to sixteen parallel blocks.  This macro
   increments `round'.  */
#define ROUND_INVERSE(which, a0, a1, a2, a3, a4, b0, b1, b2, b3, b4) \
	LINEAR_TRANSFORMATION_INVERSE (a0, a1, a2, a3, a4);	\
		LINEAR_TRANSFORMATION_INVERSE (b0, b1, b2, b3, b4);	\
	SBOX_INVERSE (which, a0, a1, a2, a3, a4);		\
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, round);		\
		SBOX_INVERSE (which, b0, b1, b2, b3, b4);		\
		BLOCK_XOR_KEY (b0, b1, b2, b3, b4, round);		\
	.set round, (round - 1);

/* Apply the first inverse Serpent round to sixteen parallel blocks.  This macro
   increments `round'.  */
#define ROUND_FIRST_INVERSE(which, a0, a1, a2, a3, a4, b0, b1, b2, b3, b4) \
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, round);	\
		BLOCK_XOR_KEY (b0, b1, b2, b3, b4, round);	\
	.set round, (round - 1);			\
	SBOX_INVERSE (which, a0, a1, a2, a3, a4); 	\
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, round);	\
		SBOX_INVERSE (which, b0, b1, b2, b3, b4); 	\
		BLOCK_XOR_KEY (b0, b1, b2, b3, b4, round);	\
	.set round, (round - 1);

.text

.align 8
.type   __serpent_enc_blk16,@function;
__serpent_enc_blk16:
	/* input:
	 *	%rdi: ctx, CTX
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: sixteen parallel
	 *						plaintext blocks
	 * output:
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: sixteen parallel
	 * 						ciphertext blocks
	 */

	/* record input vector names for __serpent_enc_blk16 */
	.set enc_in_a0, RA0
	.set enc_in_a1, RA1
	.set enc_in_a2, RA2
	.set enc_in_a3, RA3
	.set enc_in_b0, RB0
	.set enc_in_b1, RB1
	.set enc_in_b2, RB2
	.set enc_in_b3, RB3

	vpcmpeqd RNOT, RNOT, RNOT;

	transpose_4x4(RA0, RA1, RA2, RA3, RA4, RTMP0, RTMP1);
	transpose_4x4(RB0, RB1, RB2, RB3, RB4, RTMP0, RTMP1);

	.set round, 0
	ROUND (0, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (1, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (2, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (3, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (4, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (5, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (6, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (7, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (0, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (1, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (2, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (3, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (4, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (5, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (6, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (7, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (0, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (1, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (2, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (3, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (4, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (5, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (6, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (7, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (0, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (1, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (2, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (3, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (4, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (5, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND (6, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);

	ROUND_LAST (7, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);

	transpose_4x4(RA0, RA1, RA2, RA3, RA4, RTMP0, RTMP1);
	transpose_4x4(RB0, RB1, RB2, RB3, RB4, RTMP0, RTMP1);

	/* record output vector names for __serpent_enc_blk16 */
	.set enc_out_a0, RA0
	.set enc_out_a1, RA1
	.set enc_out_a2, RA2
	.set enc_out_a3, RA3
	.set enc_out_b0, RB0
	.set enc_out_b1, RB1
	.set enc_out_b2, RB2
	.set enc_out_b3, RB3

	ret;
.size __serpent_enc_blk16,.-__serpent_enc_blk16;

.align 8
.type   __serpent_dec_blk16,@function;
__serpent_dec_blk16:
	/* input:
	 *	%rdi: ctx, CTX
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: sixteen parallel
	 * 						ciphertext blocks
	 * output:
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: sixteen parallel
	 *						plaintext blocks
	 */

	/* record input vector names for __serpent_dec_blk16 */
	.set dec_in_a0, RA0
	.set dec_in_a1, RA1
	.set dec_in_a2, RA2
	.set dec_in_a3, RA3
	.set dec_in_b0, RB0
	.set dec_in_b1, RB1
	.set dec_in_b2, RB2
	.set dec_in_b3, RB3

	vpcmpeqd RNOT, RNOT, RNOT;

	transpose_4x4(RA0, RA1, RA2, RA3, RA4, RTMP0, RTMP1);
	transpose_4x4(RB0, RB1, RB2, RB3, RB4, RTMP0, RTMP1);

	.set round, 32
	ROUND_FIRST_INVERSE (7, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);

	ROUND_INVERSE (6, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (5, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (4, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (3, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (2, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (1, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (0, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (7, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (6, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (5, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (4, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (3, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (2, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (1, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (0, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (7, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (6, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (5, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (4, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (3, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (2, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (1, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (0, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (7, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (6, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (5, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (4, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (3, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (2, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (1, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);
	ROUND_INVERSE (0, RA0, RA1, RA2, RA3, RA4, RB0, RB1, RB2, RB3, RB4);

	transpose_4x4(RA0, RA1, RA2, RA3, RA4, RTMP0, RTMP1);
	transpose_4x4(RB0, RB1, RB2, RB3, RB4, RTMP0, RTMP1);

	/* record output vector names for __serpent_dec_blk16 */
	.set dec_out_a0, RA0
	.set dec_out_a1, RA1
	.set dec_out_a2, RA2
	.set dec_out_a3, RA3
	.set dec_out_b0, RB0
	.set dec_out_b1, RB1
	.set dec_out_b2, RB2
	.set dec_out_b3, RB3

	ret;
.size __serpent_dec_blk16,.-__serpent_dec_blk16;

#define inc_le128(x, minus_one, tmp) \
	vpcmpeqq minus_one, x, tmp; \
	vpsubq minus_one, x, x; \
	vpslldq $8, tmp, tmp; \
	vpsubq tmp, x, x;

.align 8
.global _gcry_serpent_avx2_ctr_enc
.type   _gcry_serpent_avx2_ctr_enc,@function;
_gcry_serpent_avx2_ctr_enc:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (16 blocks)
	 *	%rdx: src (16 blocks)
	 *	%rcx: iv (big endian, 128bit)
	 */

	vzeroupper;

	.set RA0, enc_in_a0
	.set RA1, enc_in_a1
	.set RA2, enc_in_a2
	.set RA3, enc_in_a3
	.set RB0, enc_in_b0
	.set RB1, enc_in_b1
	.set RB2, enc_in_b2
	.set RB3, enc_in_b3

	vbroadcasti128 .Lbswap128_mask RIP, RTMP3;
	vpcmpeqd RNOT, RNOT, RNOT;
	vpsrldq $8, RNOT, RNOT;   /* ab: -1:0 ; cd: -1:0 */
	vpaddq RNOT, RNOT, RTMP2; /* ab: -2:0 ; cd: -2:0 */

	/* load IV and byteswap */
	vmovdqu (%rcx), RTMP4x;
	vpshufb RTMP3x, RTMP4x, RTMP4x;
	vmovdqa RTMP4x, RTMP0x;
	inc_le128(RTMP4x, RNOTx, RTMP1x);
	vinserti128 $1, RTMP4x, RTMP0, RTMP0;
	vpshufb RTMP3, RTMP0, RA0; /* +1 ; +0 */

	/* check need for handling 64-bit overflow and carry */
	cmpq $(0xffffffffffffffff - 16), (%rcx);
	ja .Lhandle_ctr_carry;

	/* construct IVs */
	vpsubq RTMP2, RTMP0, RA1; /* +3 ; +2 */
	vpshufb RTMP3, RA1, RA1;
	vpsubq RTMP2, RA1, RA2;   /* +5 ; +4 */
	vpshufb RTMP3, RA2, RA2;
	vpsubq RTMP2, RA2, RA3;   /* +7 ; +6 */
	vpshufb RTMP3, RA3, RA3;
	vpsubq RTMP2, RA3, RB0;   /* +9 ; +8 */
	vpshufb RTMP3, RB0, RB0;
	vpsubq RTMP2, RB0, RB1;   /* +11 ; +10 */
	vpshufb RTMP3, RB1, RB1;
	vpsubq RTMP2, RB1, RB2;   /* +13 ; +12 */
	vpshufb RTMP3, RB2, RB2;
	vpsubq RTMP2, RB2, RB3;   /* +15 ; +14 */
	vpshufb RTMP3, RB3, RB3;
	vpsubq RTMP2, RB3, RTMP0; /* +16 */
	vpshufb RTMP3x, RTMP0x, RTMP0x;

	jmp .Lctr_carry_done;

.Lhandle_ctr_carry:
	/* construct IVs */
	inc_le128(RTMP0, RNOT, RTMP1);
	inc_le128(RTMP0, RNOT, RTMP1);
	vpshufb RTMP3, RTMP0, RA1; /* +3 ; +2 */
	inc_le128(RTMP0, RNOT, RTMP1);
	inc_le128(RTMP0, RNOT, RTMP1);
	vpshufb RTMP3, RTMP0, RA2; /* +5 ; +4 */
	inc_le128(RTMP0, RNOT, RTMP1);
	inc_le128(RTMP0, RNOT, RTMP1);
	vpshufb RTMP3, RTMP0, RA3; /* +7 ; +6 */
	inc_le128(RTMP0, RNOT, RTMP1);
	inc_le128(RTMP0, RNOT, RTMP1);
	vpshufb RTMP3, RTMP0, RB0; /* +9 ; +8 */
	inc_le128(RTMP0, RNOT, RTMP1);
	inc_le128(RTMP0, RNOT, RTMP1);
	vpshufb RTMP3, RTMP0, RB1; /* +11 ; +10 */
	inc_le128(RTMP0, RNOT, RTMP1);
	inc_le128(RTMP0, RNOT, RTMP1);
	vpshufb RTMP3, RTMP0, RB2; /* +13 ; +12 */
	inc_le128(RTMP0, RNOT, RTMP1);
	inc_le128(RTMP0, RNOT, RTMP1);
	vpshufb RTMP3, RTMP0, RB3; /* +15 ; +14 */
	inc_le128(RTMP0, RNOT, RTMP1);
	vextracti128 $1, RTMP0, RTMP0x;
	vpshufb RTMP3x, RTMP0x, RTMP0x; /* +16 */

.align 4
.Lctr_carry_done:
	/* store new IV */
	vmovdqu RTMP0x, (%rcx);

	call __serpent_enc_blk16;

	.set RA0, enc_out_a0
	.set RA1, enc_out_a1
	.set RA2, enc_out_a2
	.set RA3, enc_out_a3
	.set RB0, enc_out_b0
	.set RB1, enc_out_b1
	.set RB2, enc_out_b2
	.set RB3, enc_out_b3

	vpxor (0 * 32)(%rdx), RA0, RA0;
	vpxor (1 * 32)(%rdx), RA1, RA1;
	vpxor (2 * 32)(%rdx), RA2, RA2;
	vpxor (3 * 32)(%rdx), RA3, RA3;
	vpxor (4 * 32)(%rdx), RB0, RB0;
	vpxor (5 * 32)(%rdx), RB1, RB1;
	vpxor (6 * 32)(%rdx), RB2, RB2;
	vpxor (7 * 32)(%rdx), RB3, RB3;

	vmovdqu RA0, (0 * 32)(%rsi);
	vmovdqu RA1, (1 * 32)(%rsi);
	vmovdqu RA2, (2 * 32)(%rsi);
	vmovdqu RA3, (3 * 32)(%rsi);
	vmovdqu RB0, (4 * 32)(%rsi);
	vmovdqu RB1, (5 * 32)(%rsi);
	vmovdqu RB2, (6 * 32)(%rsi);
	vmovdqu RB3, (7 * 32)(%rsi);

	vzeroupper;

	ret
.size _gcry_serpent_avx2_ctr_enc,.-_gcry_serpent_avx2_ctr_enc;

.align 8
.global _gcry_serpent_avx2_cbc_dec
.type   _gcry_serpent_avx2_cbc_dec,@function;
_gcry_serpent_avx2_cbc_dec:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (16 blocks)
	 *	%rdx: src (16 blocks)
	 *	%rcx: iv
	 */

	vzeroupper;

	.set RA0, dec_in_a0
	.set RA1, dec_in_a1
	.set RA2, dec_in_a2
	.set RA3, dec_in_a3
	.set RB0, dec_in_b0
	.set RB1, dec_in_b1
	.set RB2, dec_in_b2
	.set RB3, dec_in_b3

	vmovdqu (0 * 32)(%rdx), RA0;
	vmovdqu (1 * 32)(%rdx), RA1;
	vmovdqu (2 * 32)(%rdx), RA2;
	vmovdqu (3 * 32)(%rdx), RA3;
	vmovdqu (4 * 32)(%rdx), RB0;
	vmovdqu (5 * 32)(%rdx), RB1;
	vmovdqu (6 * 32)(%rdx), RB2;
	vmovdqu (7 * 32)(%rdx), RB3;

	call __serpent_dec_blk16;

	.set RA0, dec_out_a0
	.set RA1, dec_out_a1
	.set RA2, dec_out_a2
	.set RA3, dec_out_a3
	.set RB0, dec_out_b0
	.set RB1, dec_out_b1
	.set RB2, dec_out_b2
	.set RB3, dec_out_b3

	vmovdqu (%rcx), RNOTx;
	vinserti128 $1, (%rdx), RNOT, RNOT;
	vpxor RNOT, RA0, RA0;
	vpxor (0 * 32 + 16)(%rdx), RA1, RA1;
	vpxor (1 * 32 + 16)(%rdx), RA2, RA2;
	vpxor (2 * 32 + 16)(%rdx), RA3, RA3;
	vpxor (3 * 32 + 16)(%rdx), RB0, RB0;
	vpxor (4 * 32 + 16)(%rdx), RB1, RB1;
	vpxor (5 * 32 + 16)(%rdx), RB2, RB2;
	vpxor (6 * 32 + 16)(%rdx), RB3, RB3;
	vmovdqu (7 * 32 + 16)(%rdx), RNOTx;
	vmovdqu RNOTx, (%rcx); /* store new IV */

	vmovdqu RA0, (0 * 32)(%rsi);
	vmovdqu RA1, (1 * 32)(%rsi);
	vmovdqu RA2, (2 * 32)(%rsi);
	vmovdqu RA3, (3 * 32)(%rsi);
	vmovdqu RB0, (4 * 32)(%rsi);
	vmovdqu RB1, (5 * 32)(%rsi);
	vmovdqu RB2, (6 * 32)(%rsi);
	vmovdqu RB3, (7 * 32)(%rsi);

	vzeroupper;

	ret
.size _gcry_serpent_avx2_cbc_dec,.-_gcry_serpent_avx2_cbc_dec;

.align 8
.global _gcry_serpent_avx2_cfb_dec
.type   _gcry_serpent_avx2_cfb_dec,@function;
_gcry_serpent_avx2_cfb_dec:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (16 blocks)
	 *	%rdx: src (16 blocks)
	 *	%rcx: iv
	 */

	vzeroupper;

	.set RA0, enc_in_a0
	.set RA1, enc_in_a1
	.set RA2, enc_in_a2
	.set RA3, enc_in_a3
	.set RB0, enc_in_b0
	.set RB1, enc_in_b1
	.set RB2, enc_in_b2
	.set RB3, enc_in_b3

	/* Load input */
	vmovdqu (%rcx), RNOTx;
	vinserti128 $1, (%rdx), RNOT, RA0;
	vmovdqu (0 * 32 + 16)(%rdx), RA1;
	vmovdqu (1 * 32 + 16)(%rdx), RA2;
	vmovdqu (2 * 32 + 16)(%rdx), RA3;
	vmovdqu (3 * 32 + 16)(%rdx), RB0;
	vmovdqu (4 * 32 + 16)(%rdx), RB1;
	vmovdqu (5 * 32 + 16)(%rdx), RB2;
	vmovdqu (6 * 32 + 16)(%rdx), RB3;

	/* Update IV */
	vmovdqu (7 * 32 + 16)(%rdx), RNOTx;
	vmovdqu RNOTx, (%rcx);

	call __serpent_enc_blk16;

	.set RA0, enc_out_a0
	.set RA1, enc_out_a1
	.set RA2, enc_out_a2
	.set RA3, enc_out_a3
	.set RB0, enc_out_b0
	.set RB1, enc_out_b1
	.set RB2, enc_out_b2
	.set RB3, enc_out_b3

	vpxor (0 * 32)(%rdx), RA0, RA0;
	vpxor (1 * 32)(%rdx), RA1, RA1;
	vpxor (2 * 32)(%rdx), RA2, RA2;
	vpxor (3 * 32)(%rdx), RA3, RA3;
	vpxor (4 * 32)(%rdx), RB0, RB0;
	vpxor (5 * 32)(%rdx), RB1, RB1;
	vpxor (6 * 32)(%rdx), RB2, RB2;
	vpxor (7 * 32)(%rdx), RB3, RB3;

	vmovdqu RA0, (0 * 32)(%rsi);
	vmovdqu RA1, (1 * 32)(%rsi);
	vmovdqu RA2, (2 * 32)(%rsi);
	vmovdqu RA3, (3 * 32)(%rsi);
	vmovdqu RB0, (4 * 32)(%rsi);
	vmovdqu RB1, (5 * 32)(%rsi);
	vmovdqu RB2, (6 * 32)(%rsi);
	vmovdqu RB3, (7 * 32)(%rsi);

	vzeroupper;

	ret
.size _gcry_serpent_avx2_cfb_dec,.-_gcry_serpent_avx2_cfb_dec;

.data
.align 16

/* For CTR-mode IV byteswap */
.Lbswap128_mask:
	.byte 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

#endif /*defined(USE_SERPENT) && defined(ENABLE_AVX2_SUPPORT)*/
#endif /*__x86_64*/
