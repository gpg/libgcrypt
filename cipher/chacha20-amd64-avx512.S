/* chacha20-amd64-avx512.S  -  AVX512 implementation of ChaCha20 cipher
 *
 * Copyright (C) 2022 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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

/*
 * Based on D. J. Bernstein reference implementation at
 * http://cr.yp.to/chacha.html:
 *
 * chacha-regs.c version 20080118
 * D. J. Bernstein
 * Public domain.
 */

#ifdef __x86_64
#include <config.h>
#if defined(HAVE_GCC_INLINE_ASM_AVX512) && \
   (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS))

.text

#include "asm-common-amd64.h"

/* register macros */
#define INPUT %rdi
#define DST   %rsi
#define SRC   %rdx
#define NBLKS %rcx
#define ROUND %eax

/* vector registers */
#define X0 %zmm0
#define X1 %zmm1
#define X2 %zmm2
#define X3 %zmm3
#define X4 %zmm4
#define X5 %zmm5
#define X6 %zmm6
#define X7 %zmm7
#define X8 %zmm8
#define X9 %zmm9
#define X10 %zmm10
#define X11 %zmm11
#define X12 %zmm12
#define X13 %zmm13
#define X14 %zmm14
#define X15 %zmm15

#define TMP0 %zmm16
#define TMP1 %zmm17

#define COUNTER_ADD %zmm18

#define X12_SAVE %zmm19
#define X13_SAVE %zmm20

#define S0 %zmm21
#define S1 %zmm22
#define S2 %zmm23
#define S3 %zmm24
#define S4 %zmm25
#define S5 %zmm26
#define S6 %zmm27
#define S7 %zmm28
#define S8 %zmm29
#define S14 %zmm30
#define S15 %zmm31

/**********************************************************************
  helper macros
 **********************************************************************/

/* 4x4 32-bit integer matrix transpose */
#define transpose_4x4(x0,x1,x2,x3,t1,t2) \
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

/* 4x4 128-bit matrix transpose */
#define transpose_16byte_4x4(x0,x1,x2,x3,t1,t2) \
	vshufi32x4 $0xee, x1, x0, t2; \
	vshufi32x4 $0x44, x1, x0, x0; \
	\
	vshufi32x4 $0x44, x3, x2, t1; \
	vshufi32x4 $0xee, x3, x2, x2; \
	\
	vshufi32x4 $0xdd, t1, x0, x1; \
	vshufi32x4 $0x88, t1, x0, x0; \
	\
	vshufi32x4 $0xdd, x2, t2, x3; \
	vshufi32x4 $0x88, x2, t2, x2;

#define xor_src_dst_4x4(dst, src, offset, add, x0, x4, x8, x12) \
	vpxord (offset + 0 * (add))(src), x0, x0; \
	vpxord (offset + 1 * (add))(src), x4, x4; \
	vpxord (offset + 2 * (add))(src), x8, x8; \
	vpxord (offset + 3 * (add))(src), x12, x12; \
	vmovdqu32 x0, (offset + 0 * (add))(dst); \
	vmovdqu32 x4, (offset + 1 * (add))(dst); \
	vmovdqu32 x8, (offset + 2 * (add))(dst); \
	vmovdqu32 x12, (offset + 3 * (add))(dst);

#define xor_src_dst(dst, src, offset, xreg) \
	vpxord offset(src), xreg, xreg; \
	vmovdqu32 xreg, offset(dst);

#define clear_vec4(v0,v1,v2,v3) \
	vpxord v0, v0, v0; \
	vpxord v1, v1, v1; \
	vpxord v2, v2, v2; \
	vpxord v3, v3, v3;

#define clear_zmm16_zmm31() \
	clear_vec4(%xmm16, %xmm20, %xmm24, %xmm28); \
	clear_vec4(%xmm17, %xmm21, %xmm25, %xmm29); \
	clear_vec4(%xmm18, %xmm22, %xmm26, %xmm30); \
	clear_vec4(%xmm19, %xmm23, %xmm27, %xmm31);

/**********************************************************************
  16-way chacha20
 **********************************************************************/

#define ROTATE2(v1,v2,c)	\
	vprold $(c), v1, v1;	\
	vprold $(c), v2, v2;

#define XOR(ds,s) \
	vpxord s, ds, ds;

#define PLUS(ds,s) \
	vpaddd s, ds, ds;

#define QUARTERROUND2(a1,b1,c1,d1,a2,b2,c2,d2)			\
	PLUS(a1,b1); PLUS(a2,b2); XOR(d1,a1); XOR(d2,a2);	\
	    ROTATE2(d1, d2, 16);				\
	PLUS(c1,d1); PLUS(c2,d2); XOR(b1,c1); XOR(b2,c2);	\
	    ROTATE2(b1, b2, 12);				\
	PLUS(a1,b1); PLUS(a2,b2); XOR(d1,a1); XOR(d2,a2);	\
	    ROTATE2(d1, d2, 8);					\
	PLUS(c1,d1); PLUS(c2,d2); XOR(b1,c1); XOR(b2,c2);	\
	    ROTATE2(b1, b2, 7);

.align 64
ELF(.type _gcry_chacha20_amd64_avx512_data,@object;)
_gcry_chacha20_amd64_avx512_data:
.Linc_counter:
	.byte 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
.Lone:
	.long 1,0,0,0
ELF(.size _gcry_chacha20_amd64_avx512_data,.-_gcry_chacha20_amd64_avx512_data)

.align 16
.globl _gcry_chacha20_amd64_avx512_blocks16
ELF(.type _gcry_chacha20_amd64_avx512_blocks16,@function;)
_gcry_chacha20_amd64_avx512_blocks16:
	/* input:
	 *	%rdi: input
	 *	%rsi: dst
	 *	%rdx: src
	 *	%rcx: nblks (multiple of 16)
	 */
	CFI_STARTPROC();

	vpxord %xmm16, %xmm16, %xmm16;
	vpopcntb %zmm16, %zmm16; /* spec stop for old AVX512 CPUs */

	vpmovzxbd .Linc_counter rRIP, COUNTER_ADD;

	/* Preload state */
	vpbroadcastd (0 * 4)(INPUT), S0;
	vpbroadcastd (1 * 4)(INPUT), S1;
	vpbroadcastd (2 * 4)(INPUT), S2;
	vpbroadcastd (3 * 4)(INPUT), S3;
	vpbroadcastd (4 * 4)(INPUT), S4;
	vpbroadcastd (5 * 4)(INPUT), S5;
	vpbroadcastd (6 * 4)(INPUT), S6;
	vpbroadcastd (7 * 4)(INPUT), S7;
	vpbroadcastd (8 * 4)(INPUT), S8;
	vpbroadcastd (14 * 4)(INPUT), S14;
	vpbroadcastd (15 * 4)(INPUT), S15;

.align 16
.Loop16:
	movl $20, ROUND;

	/* Construct counter vectors X12 and X13 */
	vpbroadcastd (12 * 4)(INPUT), X12;
	vpbroadcastd (13 * 4)(INPUT), X13;
	vpaddd COUNTER_ADD, X12, X12;
	vpcmpud $6, X12, COUNTER_ADD, %k2;
	vpaddd .Lone rRIP {1to16}, X13, X13{%k2};
	vmovdqa32 X12, X12_SAVE;
	vmovdqa32 X13, X13_SAVE;

	/* Load vectors */
	vmovdqa32 S0, X0;
	vmovdqa32 S4, X4;
	vmovdqa32 S8, X8;
	vmovdqa32 S1, X1;
	vmovdqa32 S5, X5;
	vpbroadcastd (9 * 4)(INPUT), X9;
	QUARTERROUND2(X0, X4,  X8, X12,   X1, X5,  X9, X13)
	vmovdqa32 S2, X2;
	vmovdqa32 S6, X6;
	vpbroadcastd (10 * 4)(INPUT), X10;
	vmovdqa32 S14, X14;
	vmovdqa32 S3, X3;
	vmovdqa32 S7, X7;
	vpbroadcastd (11 * 4)(INPUT), X11;
	vmovdqa32 S15, X15;

	/* Update counter */
	addq $16, (12 * 4)(INPUT);
	jmp .Lround2_entry;

.align 16
.Lround2:
	QUARTERROUND2(X2, X7,  X8, X13,   X3, X4,  X9, X14)
	QUARTERROUND2(X0, X4,  X8, X12,   X1, X5,  X9, X13)
.Lround2_entry:
	subl $2, ROUND;
	QUARTERROUND2(X2, X6, X10, X14,   X3, X7, X11, X15)
	QUARTERROUND2(X0, X5, X10, X15,   X1, X6, X11, X12)
	jnz .Lround2;

.Lround2_end:
	PLUS(X0, S0);
	PLUS(X1, S1);
	PLUS(X5, S5);
	PLUS(X6, S6);
	PLUS(X10, (10 * 4)(INPUT){1to16});
	PLUS(X11, (11 * 4)(INPUT){1to16});
	PLUS(X15, S15);
	PLUS(X12, X12_SAVE);
	QUARTERROUND2(X2, X7,  X8, X13,   X3, X4,  X9, X14)

	PLUS(X2, S2);
	PLUS(X3, S3);
	PLUS(X4, S4);
	PLUS(X7, S7);
	transpose_4x4(X0, X1, X2, X3, TMP0, TMP1);
	transpose_4x4(X4, X5, X6, X7, TMP0, TMP1);
	PLUS(X8, S8);
	PLUS(X9, (9 * 4)(INPUT){1to16});
	PLUS(X13, X13_SAVE);
	PLUS(X14, S14);
	transpose_4x4(X8, X9, X10, X11, TMP0, TMP1);
	transpose_4x4(X12, X13, X14, X15, TMP0, TMP1);

	transpose_16byte_4x4(X0, X4, X8, X12, TMP0, TMP1);
	xor_src_dst_4x4(DST, SRC, (64 * 0), (64 * 4), X0, X4, X8, X12);
	transpose_16byte_4x4(X1, X5, X9, X13, TMP0, TMP1);
	xor_src_dst_4x4(DST, SRC, (64 * 1), (64 * 4), X1, X5, X9, X13);
	transpose_16byte_4x4(X2, X6, X10, X14, TMP0, TMP1);
	xor_src_dst_4x4(DST, SRC, (64 * 2), (64 * 4), X2, X6, X10, X14);
	transpose_16byte_4x4(X3, X7, X11, X15, TMP0, TMP1);
	xor_src_dst_4x4(DST, SRC, (64 * 3), (64 * 4), X3, X7, X11, X15);

	subq $16, NBLKS;
	leaq (16 * 64)(SRC), SRC;
	leaq (16 * 64)(DST), DST;
	jnz .Loop16;

	/* clear the used vector registers */
	clear_zmm16_zmm31();
	kxord %k2, %k2, %k2;
	vzeroall; /* clears ZMM0-ZMM15 */

	/* eax zeroed by round loop. */
	ret_spec_stop;
	CFI_ENDPROC();
ELF(.size _gcry_chacha20_amd64_avx512_blocks16,
	  .-_gcry_chacha20_amd64_avx512_blocks16;)

#endif /*defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS)*/
#endif /*__x86_64*/
