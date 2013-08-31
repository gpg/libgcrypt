/* sha512-armv7-neon.S  -  ARM/NEON assembly implementation of SHA-512 transform
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

#include <config.h>

#if defined(HAVE_ARM_ARCH_V6) && defined(__ARMEL__) && \
    defined(HAVE_COMPATIBLE_GCC_ARM_PLATFORM_AS) && \
    defined(HAVE_GCC_INLINE_ASM_NEON)

.text

.syntax unified
.fpu neon
.arm

/* structure of SHA512_CONTEXT */
#define hd_a 0
#define hd_b ((hd_a) + 8)
#define hd_c ((hd_b) + 8)
#define hd_d ((hd_c) + 8)
#define hd_e ((hd_d) + 8)
#define hd_f ((hd_e) + 8)
#define hd_g ((hd_f) + 8)

/* register macros */
#define RK %r2

#define RA d0
#define RB d1
#define RC d2
#define RD d3
#define RE d4
#define RF d5
#define RG d6
#define RH d7

#define RT0 d8
#define RT1 d9
#define RT2 d10
#define RT3 d11
#define RT4 d12
#define RT5 d13
#define RT6 d14
#define RT7 d15

#define RW0 d16
#define RW1 d17
#define RW2 d18
#define RW3 d19
#define RW4 d20
#define RW5 d21
#define RW6 d22
#define RW7 d23
#define RW8 d24
#define RW9 d25
#define RW10 d26
#define RW11 d27
#define RW12 d28
#define RW13 d29
#define RW14 d30
#define RW15 d31

#define RW01q q8
#define RW23q q9
#define RW45q q10
#define RW67q q11
#define RW89q q12
#define RW1011q q13
#define RW1213q q14
#define RW1415q q15

/***********************************************************************
 * ARM assembly implementation of sha512 transform
 ***********************************************************************/
#define round_0_63(ra, rb, rc, rd, re, rf, rg, rh, rw0, rw14, rw9, rw1) \
	/* t1 = h + Sum1 (e) + Ch (e, f, g) + k[t] + w[t]; */ \
	vshr.u64 RT1, re, #14; \
	vshl.u64 RT3, re, #64 - 14; \
	vshr.u64 RT4, re, #18; \
	vshl.u64 RT5, re, #64 - 18; \
	veor.64 RT1, RT1, RT3; \
	vld1.64 {RT0}, [RK]!; \
	veor.64 RT1, RT1, RT4; \
	vshr.u64 RT3, re, #41; \
	vshl.u64 RT4, re, #64 - 41; \
	veor.64 RT1, RT1, RT5; \
	vadd.u64 RT0, RT0, rw0; \
	veor.64 RT1, RT1, RT3; \
	vand.64 RT2, re, rf; \
	veor.64 RT1, RT1, RT4; \
	vbic.64 RT6, rg, re; \
	\
	vadd.u64 RT1, RT1, rh; \
	veor.64 RT2, RT2, RT6; \
	vshr.u64 rh, ra, #28; \
	vshl.u64 RT3, ra, #64 - 28; \
	vadd.u64 RT1, RT1, RT0; \
	vshr.u64 RT4, ra, #34; \
	veor.64 rh, rh, RT3; \
	vshl.u64 RT5, ra, #64 - 34; \
	vadd.u64 RT1, RT1, RT2; \
	\
	/* h = Sum0 (a) + Maj (a, b, c); */ \
	veor.64 rh, rh, RT4; \
	vshr.u64 RT3, ra, #39; \
	vshl.u64 RT4, ra, #64 - 39; \
	vorr.64 RT6, ra, rb; \
	vand.64 RT0, ra, rb; \
	veor.64 rh, rh, RT5; \
	vand.64 RT6, RT6, rc; \
	veor.64 rh, rh, RT3; \
	vorr.64 RT0, RT0, RT6; \
	veor.64 rh, rh, RT4; \
	vshr.u64 RT4, rw14, #19; \
	vadd.u64 rh, rh, RT0; \
	vshl.u64 RT2, rw14, #64 - 19; \
	\
	/* w[0] += S1 (w[14]) + w[9] + S0 (w[1]); */ \
	vshr.u64 RT3, rw14, #61; \
	vshl.u64 RT6, rw14, #64 - 61; \
	veor.64 RT0, RT4, RT2; \
	vshr.u64 RT2, rw14, 6; \
	veor.64 RT0, RT0, RT3; \
	vshr.u64 RT7, rw1, #1; \
	veor.64 RT0, RT0, RT6; \
	vshl.u64 RT4, rw1, #64 - 1; \
	veor.64 RT0, RT0, RT2; \
	vshr.u64 RT5, rw1, #8; \
	vadd.u64 rw0, rw0, RT0; \
	vshl.u64 RT6, rw1, #64 - 8; \
	veor.64 RT7, RT7, RT4; \
	vshr.u64 RT4, rw1, 7; \
	veor.64 RT7, RT7, RT5; \
	vadd.u64 rw0, rw0, rw9; /* w[0]+=w[9]; */\
	veor.64 RT7, RT7, RT6; \
	vadd.u64 rd, rd, RT1; /* d+=t1; */ \
	veor.64 RT7, RT7, RT4; \
	vadd.u64 rh, rh, RT1; /* h+=t1; */ \
	vadd.u64 rw0, rw0, RT7; \

#define round_64_79(ra, rb, rc, rd, re, rf, rg, rh, rw0) \
	/* t1 = h + Sum1 (e) + Ch (e, f, g) + k[t] + w[t]; */ \
	vld1.64 {RT0}, [RK]!; \
	vshr.u64 RT1, re, #14; \
	vshl.u64 RT3, re, #64 - 14; \
	vshr.u64 RT4, re, #18; \
	vshl.u64 RT5, re, #64 - 18; \
	veor.64 RT1, RT1, RT3; \
	vshr.u64 RT7, ra, #28; \
	veor.64 RT1, RT1, RT4; \
	vshr.u64 RT3, re, #41; \
	vshl.u64 RT4, re, #64 - 41; \
	veor.64 RT1, RT1, RT5; \
	vadd.u64 RT0, RT0, rw0; \
	veor.64 RT1, RT1, RT3; \
	vand.64 RT2, re, rf; \
	veor.64 RT1, RT1, RT4; \
	vbic.64 RT6, rg, re; \
	\
	vadd.u64 RT1, RT1, rh; \
	veor.64 RT2, RT2, RT6; \
	vadd.u64 RT1, RT1, RT0; \
	vshr.u64 RT4, ra, #34; \
	vshl.u64 RT5, ra, #64 - 34; \
	\
	/* t7 = Sum0 (a) + Maj (a, b, c); */ \
	vshl.u64 RT6, ra, #64 - 28; \
	veor.64 RT7, RT7, RT4; \
	vshr.u64 RT3, ra, #39; \
	veor.64 RT7, RT7, RT6; \
	vshl.u64 RT4, ra, #64 - 39; \
	vorr.64 RT6, ra, rb; \
	vand.64 RT0, ra, rb; \
	veor.64 RT7, RT7, RT5; \
	vand.64 RT6, RT6, rc; \
	veor.64 RT7, RT7, RT3; \
	vorr.64 RT0, RT0, RT6; \
	veor.64 RT7, RT7, RT4; \
	vadd.u64 RT1, RT1, RT2; \
	vadd.u64 RT7, RT7, RT0; \
	vadd.u64 rd, rd, RT1; /* d+=t1; */ \
	vadd.u64 rh, RT7, RT1; /* h=t7+t1; */

.align 3
.globl _gcry_sha512_transform_armv7_neon
.type  _gcry_sha512_transform_armv7_neon,%function;

_gcry_sha512_transform_armv7_neon:
	/* Input:
	 *	%r0: SHA512_CONTEXT
	 *	%r1: data
	 *	%r2: u64 k[] constants
	 */
	mov %r3, #0;

	/* Load context to d0-d7 */
	vld1.64 {RA-RD}, [%r0]!;
	vld1.64 {RE-RH}, [%r0];
	sub %r0, #(4*8);

	/* Load input to w[16], d16-d31 */
	/* NOTE: Assumes that on ARMv7 unaligned accesses are always allowed. */
	vld1.64 {RW0-RW3}, [%r1]!;
	vld1.64 {RW4-RW7}, [%r1]!;
	vld1.64 {RW8-RW11}, [%r1]!;
	vld1.64 {RW12-RW15}, [%r1];
#ifdef __ARMEL__
	/* byteswap */
	vrev64.8 RW01q, RW01q;
	vrev64.8 RW23q, RW23q;
	vrev64.8 RW45q, RW45q;
	vrev64.8 RW67q, RW67q;
	vrev64.8 RW89q, RW89q;
	vrev64.8 RW1011q, RW1011q;
	vrev64.8 RW1213q, RW1213q;
	vrev64.8 RW1415q, RW1415q;
#endif

	/* EABI says that d8-d15 must be preserved by callee. */
	vpush {RT0-RT7};

.Loop:
	add %r3, #16;
	round_0_63(RA, RB, RC, RD, RE, RF, RG, RH, RW0, RW14, RW9, RW1);
	cmp %r3, #64;
	round_0_63(RH, RA, RB, RC, RD, RE, RF, RG, RW1, RW15, RW10, RW2);
	round_0_63(RG, RH, RA, RB, RC, RD, RE, RF, RW2, RW0, RW11, RW3);
	round_0_63(RF, RG, RH, RA, RB, RC, RD, RE, RW3, RW1, RW12, RW4);
	round_0_63(RE, RF, RG, RH, RA, RB, RC, RD, RW4, RW2, RW13, RW5);
	round_0_63(RD, RE, RF, RG, RH, RA, RB, RC, RW5, RW3, RW14, RW6);
	round_0_63(RC, RD, RE, RF, RG, RH, RA, RB, RW6, RW4, RW15, RW7);
	round_0_63(RB, RC, RD, RE, RF, RG, RH, RA, RW7, RW5, RW0, RW8);
	round_0_63(RA, RB, RC, RD, RE, RF, RG, RH, RW8, RW6, RW1, RW9);
	round_0_63(RH, RA, RB, RC, RD, RE, RF, RG, RW9, RW7, RW2, RW10);
	round_0_63(RG, RH, RA, RB, RC, RD, RE, RF, RW10, RW8, RW3, RW11);
	round_0_63(RF, RG, RH, RA, RB, RC, RD, RE, RW11, RW9, RW4, RW12);
	round_0_63(RE, RF, RG, RH, RA, RB, RC, RD, RW12, RW10, RW5, RW13);
	round_0_63(RD, RE, RF, RG, RH, RA, RB, RC, RW13, RW11, RW6, RW14);
	round_0_63(RC, RD, RE, RF, RG, RH, RA, RB, RW14, RW12, RW7, RW15);
	round_0_63(RB, RC, RD, RE, RF, RG, RH, RA, RW15, RW13, RW8, RW0);
	bne .Loop;

	round_64_79(RA, RB, RC, RD, RE, RF, RG, RH, RW0);
	round_64_79(RH, RA, RB, RC, RD, RE, RF, RG, RW1);
	round_64_79(RG, RH, RA, RB, RC, RD, RE, RF, RW2);
	round_64_79(RF, RG, RH, RA, RB, RC, RD, RE, RW3);
	round_64_79(RE, RF, RG, RH, RA, RB, RC, RD, RW4);
	round_64_79(RD, RE, RF, RG, RH, RA, RB, RC, RW5);
	round_64_79(RC, RD, RE, RF, RG, RH, RA, RB, RW6);
	round_64_79(RB, RC, RD, RE, RF, RG, RH, RA, RW7);
	round_64_79(RA, RB, RC, RD, RE, RF, RG, RH, RW8);
	round_64_79(RH, RA, RB, RC, RD, RE, RF, RG, RW9);
	round_64_79(RG, RH, RA, RB, RC, RD, RE, RF, RW10);
	round_64_79(RF, RG, RH, RA, RB, RC, RD, RE, RW11);
	round_64_79(RE, RF, RG, RH, RA, RB, RC, RD, RW12);
	round_64_79(RD, RE, RF, RG, RH, RA, RB, RC, RW13);
	round_64_79(RC, RD, RE, RF, RG, RH, RA, RB, RW14);
	round_64_79(RB, RC, RD, RE, RF, RG, RH, RA, RW15);

	/* Load context to d16-d23 */
	vld1.64 {RW0-RW3}, [%r0]!;
	vld1.64 {RW4-RW7}, [%r0];
	sub %r0, #(4*8);

	vadd.u64 RA, RW0;
	vadd.u64 RB, RW1;
	vadd.u64 RC, RW2;
	vadd.u64 RD, RW3;
	vadd.u64 RE, RW4;
	vadd.u64 RF, RW5;
	vadd.u64 RG, RW6;
	vadd.u64 RH, RW7;

	/* Store the first half of context */
	vst1.64 {RA-RD}, [%r0]!;

	/* Clear used registers */
	/* d16-d31 */
	veor.u64 RW01q, RW01q;
	veor.u64 RW23q, RW23q;
	veor.u64 RW45q, RW45q;
	veor.u64 RW67q, RW67q;
	vst1.64 {RE-RH}, [%r0]; /* Store the last half of context */
	veor.u64 RW89q, RW89q;
	veor.u64 RW1011q, RW1011q;
	veor.u64 RW1213q, RW1213q;
	veor.u64 RW1415q, RW1415q;
	/* d8-d15 */
	vpop {RT0-RT7};
	/* d0-d7 (q0-q3) */
	veor.u64 %q0, %q0;
	veor.u64 %q1, %q1;
	veor.u64 %q2, %q2;
	veor.u64 %q3, %q3;

	bx %lr;
.size _gcry_sha512_transform_armv7_neon,.-_gcry_sha512_transform_armv7_neon;

#endif
