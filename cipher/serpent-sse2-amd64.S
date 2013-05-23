/* serpent-sse2-amd64.S  -  SSE2 implementation of Serpent cipher
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
#if defined(USE_SERPENT)

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
.set RA0, %xmm0
.set RA1, %xmm1
.set RA2, %xmm2
.set RA3, %xmm3
.set RA4, %xmm4

.set RB0, %xmm5
.set RB1, %xmm6
.set RB2, %xmm7
.set RB3, %xmm8
.set RB4, %xmm9

.set RNOT, %xmm10
.set RTMP0, %xmm11
.set RTMP1, %xmm12
.set RTMP2, %xmm13

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
	movdqa reg, tmp; 		\
	pslld $(nleft), tmp;		\
	psrld $(32 - (nleft)), reg;	\
	por tmp, reg;

/* vector 32-bit rotation to right */
#define vec_ror(reg, nright, tmp) \
	vec_rol(reg, 32 - nright, tmp)

/* 4x4 32-bit integer matrix transpose */
#define transpose_4x4(x0, x1, x2, x3, t1, t2, t3) \
	movdqa    x0, t2; \
	punpckhdq x1, t2; \
	punpckldq x1, x0; \
	\
	movdqa    x2, t1; \
	punpckldq x3, t1; \
	punpckhdq x3, x2; \
	\
	movdqa     x0, x1; \
	punpckhqdq t1, x1; \
	punpcklqdq t1, x0; \
	\
	movdqa     t2, x3; \
	punpckhqdq x2, x3; \
	punpcklqdq x2, t2; \
	movdqa     t2, x2;

/* fill xmm register with 32-bit value from memory */
#define pbroadcastd(mem32, xreg) \
	movd mem32, xreg; \
	pshufd $0, xreg, xreg;

/* xor with unaligned memory operand */
#define pxor_u(umem128, xreg, t) \
	movdqu umem128, t; \
	pxor t, xreg;

/* 128-bit wide byte swap */
#define pbswap(xreg, t0) \
	/* reorder 32-bit words, [a,b,c,d] => [d,c,b,a] */ \
	pshufd $0x1b, xreg, xreg; \
	/* reorder high&low 16-bit words, [d0,d1,c0,c1] => [d1,d0,c1,c0] */ \
	pshuflw $0xb1, xreg, xreg; \
	pshufhw $0xb1, xreg, xreg; \
	/* reorder bytes in 16-bit words */ \
	movdqa xreg, t0; \
	psrlw $8, t0; \
	psllw $8, xreg; \
	por t0, xreg;

/**********************************************************************
  8-way serpent
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
	pxor	r0, r3;		movdqa	r1, r4;		\
	pand	r3, r1;		pxor	r2, r4;		\
	pxor	r0, r1;		por	r3, r0;		\
	pxor	r4, r0;		pxor	r3, r4;		\
	pxor	r2, r3;		por	r1, r2;		\
	pxor	r4, r2;		pxor	RNOT, r4;	\
	por	r1, r4;		pxor	r3, r1;		\
	pxor	r4, r1;		por	r0, r3;		\
	pxor	r3, r1;		pxor	r3, r4;		\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r4,r2,r0,r3);

#define SBOX0_INVERSE(r0, r1, r2, r3, r4) \
	pxor	RNOT, r2;	movdqa	r1, r4;		\
	por	r0, r1;		pxor	RNOT, r4;	\
	pxor	r2, r1;		por	r4, r2;		\
	pxor	r3, r1;		pxor	r4, r0;		\
	pxor	r0, r2;		pand	r3, r0;		\
	pxor	r0, r4;		por	r1, r0;		\
	pxor	r2, r0;		pxor	r4, r3;		\
	pxor	r1, r2;		pxor	r0, r3;		\
	pxor	r1, r3;	\
	pand	r3, r2;	\
	pxor	r2, r4;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r0,r4,r1,r3,r2);

#define SBOX1(r0, r1, r2, r3, r4) \
	pxor	RNOT, r0;	pxor	RNOT, r2;	\
	movdqa	r0, r4;		pand	r1, r0;		\
	pxor	r0, r2;		por	r3, r0;		\
	pxor	r2, r3;		pxor	r0, r1;		\
	pxor	r4, r0;		por	r1, r4;		\
	pxor	r3, r1;		por	r0, r2;		\
	pand	r4, r2;		pxor	r1, r0;		\
	pand	r2, r1;	\
	pxor	r0, r1;		pand	r2, r0;		\
	pxor	r4, r0;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r2,r0,r3,r1,r4);

#define SBOX1_INVERSE(r0, r1, r2, r3, r4) \
	movdqa	r1, r4;		pxor	r3, r1;		\
	pand	r1, r3;		pxor	r2, r4;		\
	pxor	r0, r3;		por	r1, r0;		\
	pxor	r3, r2;		pxor	r4, r0;		\
	por	r2, r0;		pxor	r3, r1;		\
	pxor	r1, r0;		por	r3, r1;		\
	pxor	r0, r1;		pxor	RNOT, r4;	\
	pxor	r1, r4;		por	r0, r1;		\
	pxor	r0, r1;	\
	por	r4, r1;	\
	pxor	r1, r3;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r4,r0,r3,r2,r1);

#define SBOX2(r0, r1, r2, r3, r4) \
	movdqa	r0, r4;		pand	r2, r0;		\
	pxor	r3, r0;		pxor	r1, r2;		\
	pxor	r0, r2;		por	r4, r3;		\
	pxor	r1, r3;		pxor	r2, r4;		\
	movdqa	r3, r1;		por	r4, r3;		\
	pxor	r0, r3;		pand	r1, r0;		\
	pxor	r0, r4;		pxor	r3, r1;		\
	pxor	r4, r1;		pxor	RNOT, r4;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r2,r3,r1,r4,r0);

#define SBOX2_INVERSE(r0, r1, r2, r3, r4) \
	pxor	r3, r2;		pxor	r0, r3;		\
	movdqa	r3, r4;		pand	r2, r3;		\
	pxor	r1, r3;		por	r2, r1;		\
	pxor	r4, r1;		pand	r3, r4;		\
	pxor	r3, r2;		pand	r0, r4;		\
	pxor	r2, r4;		pand	r1, r2;		\
	por	r0, r2;		pxor	RNOT, r3;	\
	pxor	r3, r2;		pxor	r3, r0;		\
	pand	r1, r0;		pxor	r4, r3;		\
	pxor	r0, r3;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r4,r2,r3,r0);

#define SBOX3(r0, r1, r2, r3, r4) \
	movdqa	r0, r4;		por	r3, r0;		\
	pxor	r1, r3;		pand	r4, r1;		\
	pxor	r2, r4;		pxor	r3, r2;		\
	pand	r0, r3;		por	r1, r4;		\
	pxor	r4, r3;		pxor	r1, r0;		\
	pand	r0, r4;		pxor	r3, r1;		\
	pxor	r2, r4;		por	r0, r1;		\
	pxor	r2, r1;		pxor	r3, r0;		\
	movdqa	r1, r2;		por	r3, r1;		\
	pxor	r0, r1;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r2,r3,r4,r0);

#define SBOX3_INVERSE(r0, r1, r2, r3, r4) \
	movdqa	r2, r4;		pxor	r1, r2;		\
	pxor	r2, r0;		pand	r2, r4;		\
	pxor	r0, r4;		pand	r1, r0;		\
	pxor	r3, r1;		por	r4, r3;		\
	pxor	r3, r2;		pxor	r3, r0;		\
	pxor	r4, r1;		pand	r2, r3;		\
	pxor	r1, r3;		pxor	r0, r1;		\
	por	r2, r1;		pxor	r3, r0;		\
	pxor	r4, r1;	\
	pxor	r1, r0;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r2,r1,r3,r0,r4);

#define SBOX4(r0, r1, r2, r3, r4) \
	pxor	r3, r1;		pxor	RNOT, r3;	\
	pxor	r3, r2;		pxor	r0, r3;		\
	movdqa	r1, r4;		pand	r3, r1;		\
	pxor	r2, r1;		pxor	r3, r4;		\
	pxor	r4, r0;		pand	r4, r2;		\
	pxor	r0, r2;		pand	r1, r0;		\
	pxor	r0, r3;		por	r1, r4;		\
	pxor	r0, r4;		por	r3, r0;		\
	pxor	r2, r0;		pand	r3, r2;		\
	pxor	RNOT, r0;	pxor	r2, r4;		\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r4,r0,r3,r2);

#define SBOX4_INVERSE(r0, r1, r2, r3, r4) \
	movdqa	r2, r4;		pand	r3, r2;		\
	pxor	r1, r2;		por	r3, r1;		\
	pand	r0, r1;		pxor	r2, r4;		\
	pxor	r1, r4;		pand	r2, r1;		\
	pxor	RNOT, r0;	pxor	r4, r3;		\
	pxor	r3, r1;		pand	r0, r3;		\
	pxor	r2, r3;		pxor	r1, r0;		\
	pand	r0, r2;		pxor	r0, r3;		\
	pxor	r4, r2;	\
	por	r3, r2;		pxor	r0, r3;		\
	pxor	r1, r2;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r0,r3,r2,r4,r1);

#define SBOX5(r0, r1, r2, r3, r4) \
	pxor	r1, r0;		pxor	r3, r1;		\
	pxor	RNOT, r3;	movdqa	r1, r4;		\
	pand	r0, r1;		pxor	r3, r2;		\
	pxor	r2, r1;		por	r4, r2;		\
	pxor	r3, r4;		pand	r1, r3;		\
	pxor	r0, r3;		pxor	r1, r4;		\
	pxor	r2, r4;		pxor	r0, r2;		\
	pand	r3, r0;		pxor	RNOT, r2;	\
	pxor	r4, r0;		por	r3, r4;		\
	pxor	r4, r2;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r3,r0,r2,r4);

#define SBOX5_INVERSE(r0, r1, r2, r3, r4) \
	pxor	RNOT, r1;	movdqa	r3, r4;		\
	pxor	r1, r2;		por	r0, r3;		\
	pxor	r2, r3;		por	r1, r2;		\
	pand	r0, r2;		pxor	r3, r4;		\
	pxor	r4, r2;		por	r0, r4;		\
	pxor	r1, r4;		pand	r2, r1;		\
	pxor	r3, r1;		pxor	r2, r4;		\
	pand	r4, r3;		pxor	r1, r4;		\
	pxor	r4, r3;		pxor	RNOT, r4;	\
	pxor	r0, r3;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r4,r3,r2,r0);

#define SBOX6(r0, r1, r2, r3, r4) \
	pxor	RNOT, r2;	movdqa	r3, r4;		\
	pand	r0, r3;		pxor	r4, r0;		\
	pxor	r2, r3;		por	r4, r2;		\
	pxor	r3, r1;		pxor	r0, r2;		\
	por	r1, r0;		pxor	r1, r2;		\
	pxor	r0, r4;		por	r3, r0;		\
	pxor	r2, r0;		pxor	r3, r4;		\
	pxor	r0, r4;		pxor	RNOT, r3;	\
	pand	r4, r2;	\
	pxor	r3, r2;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r0,r1,r4,r2,r3);

#define SBOX6_INVERSE(r0, r1, r2, r3, r4) \
	pxor	r2, r0;		movdqa	r2, r4;		\
	pand	r0, r2;		pxor	r3, r4;		\
	pxor	RNOT, r2;	pxor	r1, r3;		\
	pxor	r3, r2;		por	r0, r4;		\
	pxor	r2, r0;		pxor	r4, r3;		\
	pxor	r1, r4;		pand	r3, r1;		\
	pxor	r0, r1;		pxor	r3, r0;		\
	por	r2, r0;		pxor	r1, r3;		\
	pxor	r0, r4;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r1,r2,r4,r3,r0);

#define SBOX7(r0, r1, r2, r3, r4) \
	movdqa	r1, r4;		por	r2, r1;		\
	pxor	r3, r1;		pxor	r2, r4;		\
	pxor	r1, r2;		por	r4, r3;		\
	pand	r0, r3;		pxor	r2, r4;		\
	pxor	r1, r3;		por	r4, r1;		\
	pxor	r0, r1;		por	r4, r0;		\
	pxor	r2, r0;		pxor	r4, r1;		\
	pxor	r1, r2;		pand	r0, r1;		\
	pxor	r4, r1;		pxor	RNOT, r2;	\
	por	r0, r2;	\
	pxor	r2, r4;	\
	\
	sbox_reg_rename(r0,r1,r2,r3,r4, r4,r3,r1,r0,r2);

#define SBOX7_INVERSE(r0, r1, r2, r3, r4) \
	movdqa	r2, r4;		pxor	r0, r2;		\
	pand	r3, r0;		por	r3, r4;		\
	pxor	RNOT, r2;	pxor	r1, r3;		\
	por	r0, r1;		pxor	r2, r0;		\
	pand	r4, r2;		pand	r4, r3;		\
	pxor	r2, r1;		pxor	r0, r2;		\
	por	r2, r0;		pxor	r1, r4;		\
	pxor	r3, r0;		pxor	r4, r3;		\
	por	r0, r4;		pxor	r2, r3;		\
	pxor	r2, r4;	\
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
	pbroadcastd ((ctx_keys + (round) * 16 + 0 * 4)(CTX), r4); \
	pxor r4, r0; \
	pbroadcastd ((ctx_keys + (round) * 16 + 1 * 4)(CTX), r4); \
	pxor r4, r1; \
	pbroadcastd ((ctx_keys + (round) * 16 + 2 * 4)(CTX), r4); \
	pxor r4, r2; \
	pbroadcastd ((ctx_keys + (round) * 16 + 3 * 4)(CTX), r4); \
	pxor r4, r3;

/* Apply the linear transformation to BLOCK.  */
#define LINEAR_TRANSFORMATION(r0, r1, r2, r3, r4) \
	vec_rol(r0, 13, r4);	\
	vec_rol(r2, 3, r4);	\
	pxor r0, r1;		\
	pxor r2, r1;		\
	movdqa r0, r4;		\
	pslld $3, r4;		\
	pxor r2, r3;		\
	pxor r4, r3;		\
	vec_rol(r1, 1, r4);	\
	vec_rol(r3, 7, r4);	\
	pxor r1, r0;		\
	pxor r3, r0;		\
	movdqa r1, r4;		\
	pslld $7, r4;		\
	pxor r3, r2;		\
	pxor r4, r2;		\
	vec_rol(r0, 5, r4);	\
	vec_rol(r2, 22, r4);

/* Apply the inverse linear transformation to BLOCK.  */
#define LINEAR_TRANSFORMATION_INVERSE(r0, r1, r2, r3, r4) \
	vec_ror(r2, 22, r4);	\
	vec_ror(r0, 5, r4);	\
	movdqa r1, r4;		\
	pslld $7, r4;		\
	pxor r3, r2;		\
	pxor r4, r2;		\
	pxor r1, r0;		\
	pxor r3, r0;		\
	vec_ror(r3, 7, r4);	\
	vec_ror(r1, 1, r4);	\
	movdqa r0, r4;		\
	pslld $3, r4;		\
	pxor r2, r3;		\
	pxor r4, r3;		\
	pxor r0, r1;		\
	pxor r2, r1;		\
	vec_ror(r2, 3, r4);	\
	vec_ror(r0, 13, r4);

/* Apply a Serpent round to eight parallel blocks.  This macro increments
   `round'.  */
#define ROUND(which, a0, a1, a2, a3, a4, b0, b1, b2, b3, b4) \
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, round);	\
	SBOX (which, a0, a1, a2, a3, a4);		\
		BLOCK_XOR_KEY (b0, b1, b2, b3, b4, round);	\
		SBOX (which, b0, b1, b2, b3, b4);		\
	LINEAR_TRANSFORMATION (a0, a1, a2, a3, a4);	\
		LINEAR_TRANSFORMATION (b0, b1, b2, b3, b4);	\
	.set round, (round + 1);

/* Apply the last Serpent round to eight parallel blocks.  This macro increments
   `round'.  */
#define ROUND_LAST(which, a0, a1, a2, a3, a4, b0, b1, b2, b3, b4) \
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, round);	\
	SBOX (which, a0, a1, a2, a3, a4);		\
		BLOCK_XOR_KEY (b0, b1, b2, b3, b4, round);	\
		SBOX (which, b0, b1, b2, b3, b4);		\
	.set round, (round + 1);			\
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, round);	\
		BLOCK_XOR_KEY (b0, b1, b2, b3, b4, round);	\
	.set round, (round + 1);

/* Apply an inverse Serpent round to eight parallel blocks.  This macro
   increments `round'.  */
#define ROUND_INVERSE(which, a0, a1, a2, a3, a4, b0, b1, b2, b3, b4) \
	LINEAR_TRANSFORMATION_INVERSE (a0, a1, a2, a3, a4);	\
		LINEAR_TRANSFORMATION_INVERSE (b0, b1, b2, b3, b4);	\
	SBOX_INVERSE (which, a0, a1, a2, a3, a4);		\
	BLOCK_XOR_KEY (a0, a1, a2, a3, a4, round);		\
		SBOX_INVERSE (which, b0, b1, b2, b3, b4);		\
		BLOCK_XOR_KEY (b0, b1, b2, b3, b4, round);		\
	.set round, (round - 1);

/* Apply the first inverse Serpent round to eight parallel blocks.  This macro
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
.type   __serpent_enc_blk8,@function;
__serpent_enc_blk8:
	/* input:
	 *	%rdi: ctx, CTX
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel plaintext
	 *						blocks
	 * output:
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel
	 * 						ciphertext blocks
	 */

	/* record input vector names for __serpent_enc_blk8 */
	.set enc_in_a0, RA0
	.set enc_in_a1, RA1
	.set enc_in_a2, RA2
	.set enc_in_a3, RA3
	.set enc_in_b0, RB0
	.set enc_in_b1, RB1
	.set enc_in_b2, RB2
	.set enc_in_b3, RB3

	pcmpeqd RNOT, RNOT;

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

	/* record output vector names for __serpent_enc_blk8 */
	.set enc_out_a0, RA0
	.set enc_out_a1, RA1
	.set enc_out_a2, RA2
	.set enc_out_a3, RA3
	.set enc_out_b0, RB0
	.set enc_out_b1, RB1
	.set enc_out_b2, RB2
	.set enc_out_b3, RB3

	ret;
.size __serpent_enc_blk8,.-__serpent_enc_blk8;

.align 8
.type   __serpent_dec_blk8,@function;
__serpent_dec_blk8:
	/* input:
	 *	%rdi: ctx, CTX
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel
	 * 						ciphertext blocks
	 * output:
	 *	RA0, RA1, RA2, RA3, RB0, RB1, RB2, RB3: eight parallel plaintext
	 *						blocks
	 */

	/* record input vector names for __serpent_dec_blk8 */
	.set dec_in_a0, RA0
	.set dec_in_a1, RA1
	.set dec_in_a2, RA2
	.set dec_in_a3, RA3
	.set dec_in_b0, RB0
	.set dec_in_b1, RB1
	.set dec_in_b2, RB2
	.set dec_in_b3, RB3

	pcmpeqd RNOT, RNOT;

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

	/* record output vector names for __serpent_dec_blk8 */
	.set dec_out_a0, RA0
	.set dec_out_a1, RA1
	.set dec_out_a2, RA2
	.set dec_out_a3, RA3
	.set dec_out_b0, RB0
	.set dec_out_b1, RB1
	.set dec_out_b2, RB2
	.set dec_out_b3, RB3

	ret;
.size __serpent_dec_blk8,.-__serpent_dec_blk8;

.align 8
.global _gcry_serpent_sse2_ctr_enc
.type   _gcry_serpent_sse2_ctr_enc,@function;
_gcry_serpent_sse2_ctr_enc:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (8 blocks)
	 *	%rdx: src (8 blocks)
	 *	%rcx: iv (big endian, 128bit)
	 */

	.set RA0, enc_in_a0
	.set RA1, enc_in_a1
	.set RA2, enc_in_a2
	.set RA3, enc_in_a3
	.set RB0, enc_in_b0
	.set RB1, enc_in_b1
	.set RB2, enc_in_b2
	.set RB3, enc_in_b3

	/* load IV and byteswap */
	movdqu (%rcx), RA0;
	movdqa RA0, RTMP0;
	pbswap(RTMP0, RTMP1); /* be => le */

	pcmpeqd RNOT, RNOT;
	psrldq $8, RNOT; /* low: -1, high: 0 */
	movdqa RNOT, RTMP2;
	paddq RTMP2, RTMP2; /* low: -2, high: 0 */

	/* construct IVs */
	movdqa RTMP0, RTMP1;
	psubq RNOT, RTMP0; /* +1 */
	movdqa RTMP0, RA1;
	psubq RTMP2, RTMP1; /* +2 */
	movdqa RTMP1, RA2;
	psubq RTMP2, RTMP0; /* +3 */
	movdqa RTMP0, RA3;
	psubq RTMP2, RTMP1; /* +4 */
	movdqa RTMP1, RB0;
	psubq RTMP2, RTMP0; /* +5 */
	movdqa RTMP0, RB1;
	psubq RTMP2, RTMP1; /* +6 */
	movdqa RTMP1, RB2;
	psubq RTMP2, RTMP0; /* +7 */
	movdqa RTMP0, RB3;
	psubq RTMP2, RTMP1; /* +8 */

	/* check need for handling 64-bit overflow and carry */
	cmpl $0xffffffff, 8(%rcx);
	jne .Lno_ctr_carry;

	movl 12(%rcx), %eax;
	bswapl %eax;
	cmpl $-8, %eax;
	jb .Lno_ctr_carry;
	pslldq $8, RNOT; /* low: 0, high: -1 */
	je .Lcarry_RTMP0;

	cmpl $-6, %eax;
	jb .Lcarry_RB3;
	je .Lcarry_RB2;

	cmpl $-4, %eax;
	jb .Lcarry_RB1;
	je .Lcarry_RB0;

	cmpl $-2, %eax;
	jb .Lcarry_RA3;
	je .Lcarry_RA2;

	psubq RNOT, RA1;
.Lcarry_RA2:
	psubq RNOT, RA2;
.Lcarry_RA3:
	psubq RNOT, RA3;
.Lcarry_RB0:
	psubq RNOT, RB0;
.Lcarry_RB1:
	psubq RNOT, RB1;
.Lcarry_RB2:
	psubq RNOT, RB2;
.Lcarry_RB3:
	psubq RNOT, RB3;
.Lcarry_RTMP0:
	psubq RNOT, RTMP1;

.Lno_ctr_carry:
	/* le => be */
	pbswap(RA1, RTMP0);
	pbswap(RA2, RTMP0);
	pbswap(RA3, RTMP0);
	pbswap(RB0, RTMP0);
	pbswap(RB1, RTMP0);
	pbswap(RB2, RTMP0);
	pbswap(RB3, RTMP0);
	pbswap(RTMP1, RTMP0);
	/* store new IV */
	movdqu RTMP1, (%rcx);

	call __serpent_enc_blk8;

	.set RA0, enc_out_a0
	.set RA1, enc_out_a1
	.set RA2, enc_out_a2
	.set RA3, enc_out_a3
	.set RB0, enc_out_b0
	.set RB1, enc_out_b1
	.set RB2, enc_out_b2
	.set RB3, enc_out_b3

	pxor_u((0 * 16)(%rdx), RA0, RTMP0);
	pxor_u((1 * 16)(%rdx), RA1, RTMP0);
	pxor_u((2 * 16)(%rdx), RA2, RTMP0);
	pxor_u((3 * 16)(%rdx), RA3, RTMP0);
	pxor_u((4 * 16)(%rdx), RB0, RTMP0);
	pxor_u((5 * 16)(%rdx), RB1, RTMP0);
	pxor_u((6 * 16)(%rdx), RB2, RTMP0);
	pxor_u((7 * 16)(%rdx), RB3, RTMP0);

	movdqu RA0, (0 * 16)(%rsi);
	movdqu RA1, (1 * 16)(%rsi);
	movdqu RA2, (2 * 16)(%rsi);
	movdqu RA3, (3 * 16)(%rsi);
	movdqu RB0, (4 * 16)(%rsi);
	movdqu RB1, (5 * 16)(%rsi);
	movdqu RB2, (6 * 16)(%rsi);
	movdqu RB3, (7 * 16)(%rsi);

	ret
.size _gcry_serpent_sse2_ctr_enc,.-_gcry_serpent_sse2_ctr_enc;

.align 8
.global _gcry_serpent_sse2_cbc_dec
.type   _gcry_serpent_sse2_cbc_dec,@function;
_gcry_serpent_sse2_cbc_dec:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (8 blocks)
	 *	%rdx: src (8 blocks)
	 *	%rcx: iv
	 */

	.set RA0, dec_in_a0
	.set RA1, dec_in_a1
	.set RA2, dec_in_a2
	.set RA3, dec_in_a3
	.set RB0, dec_in_b0
	.set RB1, dec_in_b1
	.set RB2, dec_in_b2
	.set RB3, dec_in_b3

	movdqu (0 * 16)(%rdx), RA0;
	movdqu (1 * 16)(%rdx), RA1;
	movdqu (2 * 16)(%rdx), RA2;
	movdqu (3 * 16)(%rdx), RA3;
	movdqu (4 * 16)(%rdx), RB0;
	movdqu (5 * 16)(%rdx), RB1;
	movdqu (6 * 16)(%rdx), RB2;
	movdqu (7 * 16)(%rdx), RB3;

	call __serpent_dec_blk8;

	.set RA0, dec_out_a0
	.set RA1, dec_out_a1
	.set RA2, dec_out_a2
	.set RA3, dec_out_a3
	.set RB0, dec_out_b0
	.set RB1, dec_out_b1
	.set RB2, dec_out_b2
	.set RB3, dec_out_b3

	movdqu (7 * 16)(%rdx), RNOT;
	pxor_u((%rcx), RA0, RTMP0);
	pxor_u((0 * 16)(%rdx), RA1, RTMP0);
	pxor_u((1 * 16)(%rdx), RA2, RTMP0);
	pxor_u((2 * 16)(%rdx), RA3, RTMP0);
	pxor_u((3 * 16)(%rdx), RB0, RTMP0);
	pxor_u((4 * 16)(%rdx), RB1, RTMP0);
	pxor_u((5 * 16)(%rdx), RB2, RTMP0);
	pxor_u((6 * 16)(%rdx), RB3, RTMP0);
	movdqu RNOT, (%rcx); /* store new IV */

	movdqu RA0, (0 * 16)(%rsi);
	movdqu RA1, (1 * 16)(%rsi);
	movdqu RA2, (2 * 16)(%rsi);
	movdqu RA3, (3 * 16)(%rsi);
	movdqu RB0, (4 * 16)(%rsi);
	movdqu RB1, (5 * 16)(%rsi);
	movdqu RB2, (6 * 16)(%rsi);
	movdqu RB3, (7 * 16)(%rsi);

	ret
.size _gcry_serpent_sse2_cbc_dec,.-_gcry_serpent_sse2_cbc_dec;

.align 8
.global _gcry_serpent_sse2_cfb_dec
.type   _gcry_serpent_sse2_cfb_dec,@function;
_gcry_serpent_sse2_cfb_dec:
	/* input:
	 *	%rdi: ctx, CTX
	 *	%rsi: dst (8 blocks)
	 *	%rdx: src (8 blocks)
	 *	%rcx: iv
	 */

	.set RA0, enc_in_a0
	.set RA1, enc_in_a1
	.set RA2, enc_in_a2
	.set RA3, enc_in_a3
	.set RB0, enc_in_b0
	.set RB1, enc_in_b1
	.set RB2, enc_in_b2
	.set RB3, enc_in_b3

	/* Load input */
	movdqu (%rcx), RA0;
	movdqu 0 * 16(%rdx), RA1;
	movdqu 1 * 16(%rdx), RA2;
	movdqu 2 * 16(%rdx), RA3;
	movdqu 3 * 16(%rdx), RB0;
	movdqu 4 * 16(%rdx), RB1;
	movdqu 5 * 16(%rdx), RB2;
	movdqu 6 * 16(%rdx), RB3;

	/* Update IV */
	movdqu 7 * 16(%rdx), RNOT;
	movdqu RNOT, (%rcx);

	call __serpent_enc_blk8;

	.set RA0, enc_out_a0
	.set RA1, enc_out_a1
	.set RA2, enc_out_a2
	.set RA3, enc_out_a3
	.set RB0, enc_out_b0
	.set RB1, enc_out_b1
	.set RB2, enc_out_b2
	.set RB3, enc_out_b3

	pxor_u((0 * 16)(%rdx), RA0, RTMP0);
	pxor_u((1 * 16)(%rdx), RA1, RTMP0);
	pxor_u((2 * 16)(%rdx), RA2, RTMP0);
	pxor_u((3 * 16)(%rdx), RA3, RTMP0);
	pxor_u((4 * 16)(%rdx), RB0, RTMP0);
	pxor_u((5 * 16)(%rdx), RB1, RTMP0);
	pxor_u((6 * 16)(%rdx), RB2, RTMP0);
	pxor_u((7 * 16)(%rdx), RB3, RTMP0);

	movdqu RA0, (0 * 16)(%rsi);
	movdqu RA1, (1 * 16)(%rsi);
	movdqu RA2, (2 * 16)(%rsi);
	movdqu RA3, (3 * 16)(%rsi);
	movdqu RB0, (4 * 16)(%rsi);
	movdqu RB1, (5 * 16)(%rsi);
	movdqu RB2, (6 * 16)(%rsi);
	movdqu RB3, (7 * 16)(%rsi);

	ret
.size _gcry_serpent_sse2_cfb_dec,.-_gcry_serpent_sse2_cfb_dec;

#endif /*defined(USE_SERPENT)*/
#endif /*__x86_64*/
