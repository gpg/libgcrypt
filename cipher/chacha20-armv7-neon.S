/* chacha20-armv7-neon.S - ARM/NEON accelerated chacha20 blocks function
 *
 * Copyright (C) 2014 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
 * Based on public domain implementation by Andrew Moon at
 *  https://github.com/floodyberry/chacha-opt
 */

#include <config.h>

#if defined(HAVE_ARM_ARCH_V6) && defined(__ARMEL__) && \
    defined(HAVE_COMPATIBLE_GCC_ARM_PLATFORM_AS) && \
    defined(HAVE_GCC_INLINE_ASM_NEON) && defined(USE_CHACHA20)

.syntax unified
.fpu neon
.arm

#define UNALIGNED_STMIA8(ptr, l0, l1, l2, l3, l4, l5, l6, l7) \
        tst ptr, #3; \
        beq 1f; \
        vpush {d0-d3}; \
        vmov s0, l0; \
        vmov s1, l1; \
        vmov s2, l2; \
        vmov s3, l3; \
        vmov s4, l4; \
        vmov s5, l5; \
        vmov s6, l6; \
        vmov s7, l7; \
        vst1.32 {d0-d3}, [ptr]; \
        add ptr, #32; \
        vpop {d0-d3}; \
        b 2f; \
     1: stmia ptr!, {l0-l7}; \
     2: ;

#define UNALIGNED_LDMIA4(ptr, l0, l1, l2, l3) \
        tst ptr, #3; \
        /*beq 1f;*/ \
        vpush {d0-d1}; \
        vld1.32 {d0-d1}, [ptr]; \
        add ptr, #16; \
        vmov l0, s0; \
        vmov l1, s1; \
        vmov l2, s2; \
        vmov l3, s3; \
        vpop {d0-d1}; \
        b 2f; \
     1: ldmia ptr!, {l0-l3}; \
     2: ;

.text

.globl _gcry_chacha20_armv7_neon_blocks
.type  _gcry_chacha20_armv7_neon_blocks,%function;
_gcry_chacha20_armv7_neon_blocks:
.Lchacha_blocks_neon_local:
	tst r3, r3
	beq .Lchacha_blocks_neon_nobytes
	vstmdb sp!, {q4,q5,q6,q7}
	stmfd sp!, {r4-r12, r14}
	mov r8, sp
	sub sp, sp, #196
	and sp, sp, #0xffffffe0
	str r0, [sp, #60]
	str r1, [sp, #48]
	str r2, [sp, #40]
	str r3, [sp, #52]
	str r8, [sp, #192]
	add r1, sp, #64
	ldmia r0!, {r4-r11}
	stmia r1!, {r4-r11}
	ldmia r0!, {r4-r11}
	stmia r1!, {r4-r11}
	mov r4, #20
	str r4, [sp, #44]
	cmp r3, #256
	blo .Lchacha_blocks_neon_mainloop2
.Lchacha_blocks_neon_mainloop1:
	ldr r0, [sp, #44]
	str r0, [sp, #0]
	add r1, sp, #(64)
	mov r2, #1
	veor q12, q12
	vld1.32 {q0,q1}, [r1,:128]!
	vld1.32 {q2,q3}, [r1,:128]
	vmov.32 d24[0], r2
	vadd.u64 q3, q3, q12
	vmov q4, q0
	vmov q5, q1
	vmov q6, q2
	vadd.u64 q7, q3, q12
	vmov q8, q0
	vmov q9, q1
	vmov q10, q2
	vadd.u64 q11, q7, q12
	add r0, sp, #64
	ldm r0, {r0-r12}
	ldr r14, [sp, #(64 +60)]
	str r6, [sp, #8]
	str r11, [sp, #12]
	str r14, [sp, #28]
	ldr r11, [sp, #(64 +52)]
	ldr r14, [sp, #(64 +56)]
.Lchacha_blocks_neon_rounds1:
	ldr r6, [sp, #0]
	vadd.i32 q0, q0, q1
	add r0, r0, r4
	vadd.i32 q4, q4, q5
	add r1, r1, r5
	vadd.i32 q8, q8, q9
	eor r12, r12, r0
	veor q12, q3, q0
	eor r11, r11, r1
	veor q13, q7, q4
	ror r12, r12, #16
	veor q14, q11, q8
	ror r11, r11, #16
	vrev32.16 q3, q12
	subs r6, r6, #2
	vrev32.16 q7, q13
	add r8, r8, r12
	vrev32.16 q11, q14
	add r9, r9, r11
	vadd.i32 q2, q2, q3
	eor r4, r4, r8
	vadd.i32 q6, q6, q7
	eor r5, r5, r9
	vadd.i32 q10, q10, q11
	str r6, [sp, #0]
	veor q12, q1, q2
	ror r4, r4, #20
	veor q13, q5, q6
	ror r5, r5, #20
	veor q14, q9, q10
	add r0, r0, r4
	vshl.i32 q1, q12, #12
	add r1, r1, r5
	vshl.i32 q5, q13, #12
	ldr r6, [sp, #8]
	vshl.i32 q9, q14, #12
	eor r12, r12, r0
	vsri.u32 q1, q12, #20
	eor r11, r11, r1
	vsri.u32 q5, q13, #20
	ror r12, r12, #24
	vsri.u32 q9, q14, #20
	ror r11, r11, #24
	vadd.i32 q0, q0, q1
	add r8, r8, r12
	vadd.i32 q4, q4, q5
	add r9, r9, r11
	vadd.i32 q8, q8, q9
	eor r4, r4, r8
	veor q12, q3, q0
	eor r5, r5, r9
	veor q13, q7, q4
	str r11, [sp, #20]
	veor q14, q11, q8
	ror r4, r4, #25
	vshl.i32 q3, q12, #8
	ror r5, r5, #25
	vshl.i32 q7, q13, #8
	str r4, [sp, #4]
	vshl.i32 q11, q14, #8
	ldr r4, [sp, #28]
	vsri.u32 q3, q12, #24
	add r2, r2, r6
	vsri.u32 q7, q13, #24
	add r3, r3, r7
	vsri.u32 q11, q14, #24
	ldr r11, [sp, #12]
	vadd.i32 q2, q2, q3
	eor r14, r14, r2
	vadd.i32 q6, q6, q7
	eor r4, r4, r3
	vadd.i32 q10, q10, q11
	ror r14, r14, #16
	veor q12, q1, q2
	ror r4, r4, #16
	veor q13, q5, q6
	add r10, r10, r14
	veor q14, q9, q10
	add r11, r11, r4
	vshl.i32 q1, q12, #7
	eor r6, r6, r10
	vshl.i32 q5, q13, #7
	eor r7, r7, r11
	vshl.i32 q9, q14, #7
	ror r6, r6, #20
	vsri.u32 q1, q12, #25
	ror r7, r7, #20
	vsri.u32 q5, q13, #25
	add r2, r2, r6
	vsri.u32 q9, q14, #25
	add r3, r3, r7
	vext.32 q3, q3, q3, #3
	eor r14, r14, r2
	vext.32 q7, q7, q7, #3
	eor r4, r4, r3
	vext.32 q11, q11, q11, #3
	ror r14, r14, #24
	vext.32 q1, q1, q1, #1
	ror r4, r4, #24
	vext.32 q5, q5, q5, #1
	add r10, r10, r14
	vext.32 q9, q9, q9, #1
	add r11, r11, r4
	vext.32 q2, q2, q2, #2
	eor r6, r6, r10
	vext.32 q6, q6, q6, #2
	eor r7, r7, r11
	vext.32 q10, q10, q10, #2
	ror r6, r6, #25
	vadd.i32 q0, q0, q1
	ror r7, r7, #25
	vadd.i32 q4, q4, q5
	add r0, r0, r5
	vadd.i32 q8, q8, q9
	add r1, r1, r6
	veor q12, q3, q0
	eor r4, r4, r0
	veor q13, q7, q4
	eor r12, r12, r1
	veor q14, q11, q8
	ror r4, r4, #16
	vrev32.16 q3, q12
	ror r12, r12, #16
	vrev32.16 q7, q13
	add r10, r10, r4
	vrev32.16 q11, q14
	add r11, r11, r12
	vadd.i32 q2, q2, q3
	eor r5, r5, r10
	vadd.i32 q6, q6, q7
	eor r6, r6, r11
	vadd.i32 q10, q10, q11
	ror r5, r5, #20
	veor q12, q1, q2
	ror r6, r6, #20
	veor q13, q5, q6
	add r0, r0, r5
	veor q14, q9, q10
	add r1, r1, r6
	vshl.i32 q1, q12, #12
	eor r4, r4, r0
	vshl.i32 q5, q13, #12
	eor r12, r12, r1
	vshl.i32 q9, q14, #12
	ror r4, r4, #24
	vsri.u32 q1, q12, #20
	ror r12, r12, #24
	vsri.u32 q5, q13, #20
	add r10, r10, r4
	vsri.u32 q9, q14, #20
	add r11, r11, r12
	vadd.i32 q0, q0, q1
	eor r5, r5, r10
	vadd.i32 q4, q4, q5
	eor r6, r6, r11
	vadd.i32 q8, q8, q9
	str r11, [sp, #12]
	veor q12, q3, q0
	ror r5, r5, #25
	veor q13, q7, q4
	ror r6, r6, #25
	veor q14, q11, q8
	str r4, [sp, #28]
	vshl.i32 q3, q12, #8
	ldr r4, [sp, #4]
	vshl.i32 q7, q13, #8
	add r2, r2, r7
	vshl.i32 q11, q14, #8
	add r3, r3, r4
	vsri.u32 q3, q12, #24
	ldr r11, [sp, #20]
	vsri.u32 q7, q13, #24
	eor r11, r11, r2
	vsri.u32 q11, q14, #24
	eor r14, r14, r3
	vadd.i32 q2, q2, q3
	ror r11, r11, #16
	vadd.i32 q6, q6, q7
	ror r14, r14, #16
	vadd.i32 q10, q10, q11
	add r8, r8, r11
	veor q12, q1, q2
	add r9, r9, r14
	veor q13, q5, q6
	eor r7, r7, r8
	veor q14, q9, q10
	eor r4, r4, r9
	vshl.i32 q1, q12, #7
	ror r7, r7, #20
	vshl.i32 q5, q13, #7
	ror r4, r4, #20
	vshl.i32 q9, q14, #7
	str r6, [sp, #8]
	vsri.u32 q1, q12, #25
	add r2, r2, r7
	vsri.u32 q5, q13, #25
	add r3, r3, r4
	vsri.u32 q9, q14, #25
	eor r11, r11, r2
	vext.32 q3, q3, q3, #1
	eor r14, r14, r3
	vext.32 q7, q7, q7, #1
	ror r11, r11, #24
	vext.32 q11, q11, q11, #1
	ror r14, r14, #24
	vext.32 q1, q1, q1, #3
	add r8, r8, r11
	vext.32 q5, q5, q5, #3
	add r9, r9, r14
	vext.32 q9, q9, q9, #3
	eor r7, r7, r8
	vext.32 q2, q2, q2, #2
	eor r4, r4, r9
	vext.32 q6, q6, q6, #2
	ror r7, r7, #25
	vext.32 q10, q10, q10, #2
	ror r4, r4, #25
	bne .Lchacha_blocks_neon_rounds1
	str r8, [sp, #0]
	str r9, [sp, #4]
	str r10, [sp, #8]
	str r12, [sp, #16]
	str r11, [sp, #20]
	str r14, [sp, #24]
	add r9, sp, #64
	vld1.32 {q12,q13}, [r9,:128]!
	ldr r12, [sp, #48]
	vld1.32 {q14,q15}, [r9,:128]
	ldr r14, [sp, #40]
	vadd.i32 q0, q0, q12
	ldr r8, [sp, #(64 +0)]
	vadd.i32 q4, q4, q12
	ldr r9, [sp, #(64 +4)]
	vadd.i32 q8, q8, q12
	ldr r10, [sp, #(64 +8)]
	vadd.i32 q1, q1, q13
	ldr r11, [sp, #(64 +12)]
	vadd.i32 q5, q5, q13
	add r0, r0, r8
	vadd.i32 q9, q9, q13
	add r1, r1, r9
	vadd.i32 q2, q2, q14
	add r2, r2, r10
	vadd.i32 q6, q6, q14
	ldr r8, [sp, #(64 +16)]
	vadd.i32 q10, q10, q14
	add r3, r3, r11
	veor q14, q14, q14
	ldr r9, [sp, #(64 +20)]
	mov r11, #1
	add r4, r4, r8
	vmov.32 d28[0], r11
	ldr r10, [sp, #(64 +24)]
	vadd.u64 q12, q14, q15
	add r5, r5, r9
	vadd.u64 q13, q14, q12
	ldr r11, [sp, #(64 +28)]
	vadd.u64 q14, q14, q13
	add r6, r6, r10
	vadd.i32 q3, q3, q12
	tst r12, r12
	vadd.i32 q7, q7, q13
	add r7, r7, r11
	vadd.i32 q11, q11, q14
	beq .Lchacha_blocks_neon_nomessage11
	UNALIGNED_LDMIA4(r12, r8, r9, r10, r11)
	tst r12, r12
	eor r0, r0, r8
	eor r1, r1, r9
	eor r2, r2, r10
	ldr r8, [r12, #0]
	eor r3, r3, r11
	ldr r9, [r12, #4]
	eor r4, r4, r8
	ldr r10, [r12, #8]
	eor r5, r5, r9
	ldr r11, [r12, #12]
	eor r6, r6, r10
	add r12, r12, #16
	eor r7, r7, r11
.Lchacha_blocks_neon_nomessage11:
	UNALIGNED_STMIA8(r14, r0, r1, r2, r3, r4, r5, r6, r7)
	tst r12, r12
	ldm sp, {r0-r7}
	ldr r8, [sp, #(64 +32)]
	ldr r9, [sp, #(64 +36)]
	ldr r10, [sp, #(64 +40)]
	ldr r11, [sp, #(64 +44)]
	add r0, r0, r8
	add r1, r1, r9
	add r2, r2, r10
	ldr r8, [sp, #(64 +48)]
	add r3, r3, r11
	ldr r9, [sp, #(64 +52)]
	add r4, r4, r8
	ldr r10, [sp, #(64 +56)]
	add r5, r5, r9
	ldr r11, [sp, #(64 +60)]
	add r6, r6, r10
	adds r8, r8, #4
	add r7, r7, r11
	adc r9, r9, #0
	str r8, [sp, #(64 +48)]
	tst r12, r12
	str r9, [sp, #(64 +52)]
	beq .Lchacha_blocks_neon_nomessage12
	UNALIGNED_LDMIA4(r12, r8, r9, r10, r11)
	tst r12, r12
	eor r0, r0, r8
	eor r1, r1, r9
	eor r2, r2, r10
	ldr r8, [r12, #0]
	eor r3, r3, r11
	ldr r9, [r12, #4]
	eor r4, r4, r8
	ldr r10, [r12, #8]
	eor r5, r5, r9
	ldr r11, [r12, #12]
	eor r6, r6, r10
	add r12, r12, #16
	eor r7, r7, r11
.Lchacha_blocks_neon_nomessage12:
	UNALIGNED_STMIA8(r14, r0, r1, r2, r3, r4, r5, r6, r7)
	tst r12, r12
	beq .Lchacha_blocks_neon_nomessage13
	vld1.32 {q12,q13}, [r12]!
	vld1.32 {q14,q15}, [r12]!
	veor q0, q0, q12
	veor q1, q1, q13
	veor q2, q2, q14
	veor q3, q3, q15
.Lchacha_blocks_neon_nomessage13:
	vst1.32 {q0,q1}, [r14]!
	vst1.32 {q2,q3}, [r14]!
	beq .Lchacha_blocks_neon_nomessage14
	vld1.32 {q12,q13}, [r12]!
	vld1.32 {q14,q15}, [r12]!
	veor q4, q4, q12
	veor q5, q5, q13
	veor q6, q6, q14
	veor q7, q7, q15
.Lchacha_blocks_neon_nomessage14:
	vst1.32 {q4,q5}, [r14]!
	vst1.32 {q6,q7}, [r14]!
	beq .Lchacha_blocks_neon_nomessage15
	vld1.32 {q12,q13}, [r12]!
	vld1.32 {q14,q15}, [r12]!
	veor q8, q8, q12
	veor q9, q9, q13
	veor q10, q10, q14
	veor q11, q11, q15
.Lchacha_blocks_neon_nomessage15:
	vst1.32 {q8,q9}, [r14]!
	vst1.32 {q10,q11}, [r14]!
	str r12, [sp, #48]
	str r14, [sp, #40]
	ldr r3, [sp, #52]
	sub r3, r3, #256
	cmp r3, #256
	str r3, [sp, #52]
	bhs .Lchacha_blocks_neon_mainloop1
	tst r3, r3
	beq .Lchacha_blocks_neon_done
.Lchacha_blocks_neon_mainloop2:
	ldr r3, [sp, #52]
	ldr r1, [sp, #48]
	cmp r3, #64
	bhs .Lchacha_blocks_neon_noswap1
	add r4, sp, #128
	mov r5, r4
	tst r1, r1
	beq .Lchacha_blocks_neon_nocopy1
.Lchacha_blocks_neon_copyinput1:
	subs r3, r3, #1
	ldrb r0, [r1], #1
	strb r0, [r4], #1
	bne .Lchacha_blocks_neon_copyinput1
	str r5, [sp, #48]
.Lchacha_blocks_neon_nocopy1:
	ldr r4, [sp, #40]
	str r5, [sp, #40]
	str r4, [sp, #56]
.Lchacha_blocks_neon_noswap1:
	ldr r0, [sp, #44]
	str r0, [sp, #0]
	add r0, sp, #64
	ldm r0, {r0-r12}
	ldr r14, [sp, #(64 +60)]
	str r6, [sp, #8]
	str r11, [sp, #12]
	str r14, [sp, #28]
	ldr r11, [sp, #(64 +52)]
	ldr r14, [sp, #(64 +56)]
.Lchacha_blocks_neon_rounds2:
	ldr r6, [sp, #0]
	add r0, r0, r4
	add r1, r1, r5
	eor r12, r12, r0
	eor r11, r11, r1
	ror r12, r12, #16
	ror r11, r11, #16
	subs r6, r6, #2
	add r8, r8, r12
	add r9, r9, r11
	eor r4, r4, r8
	eor r5, r5, r9
	str r6, [sp, #0]
	ror r4, r4, #20
	ror r5, r5, #20
	add r0, r0, r4
	add r1, r1, r5
	ldr r6, [sp, #8]
	eor r12, r12, r0
	eor r11, r11, r1
	ror r12, r12, #24
	ror r11, r11, #24
	add r8, r8, r12
	add r9, r9, r11
	eor r4, r4, r8
	eor r5, r5, r9
	str r11, [sp, #20]
	ror r4, r4, #25
	ror r5, r5, #25
	str r4, [sp, #4]
	ldr r4, [sp, #28]
	add r2, r2, r6
	add r3, r3, r7
	ldr r11, [sp, #12]
	eor r14, r14, r2
	eor r4, r4, r3
	ror r14, r14, #16
	ror r4, r4, #16
	add r10, r10, r14
	add r11, r11, r4
	eor r6, r6, r10
	eor r7, r7, r11
	ror r6, r6, #20
	ror r7, r7, #20
	add r2, r2, r6
	add r3, r3, r7
	eor r14, r14, r2
	eor r4, r4, r3
	ror r14, r14, #24
	ror r4, r4, #24
	add r10, r10, r14
	add r11, r11, r4
	eor r6, r6, r10
	eor r7, r7, r11
	ror r6, r6, #25
	ror r7, r7, #25
	add r0, r0, r5
	add r1, r1, r6
	eor r4, r4, r0
	eor r12, r12, r1
	ror r4, r4, #16
	ror r12, r12, #16
	add r10, r10, r4
	add r11, r11, r12
	eor r5, r5, r10
	eor r6, r6, r11
	ror r5, r5, #20
	ror r6, r6, #20
	add r0, r0, r5
	add r1, r1, r6
	eor r4, r4, r0
	eor r12, r12, r1
	ror r4, r4, #24
	ror r12, r12, #24
	add r10, r10, r4
	add r11, r11, r12
	eor r5, r5, r10
	eor r6, r6, r11
	str r11, [sp, #12]
	ror r5, r5, #25
	ror r6, r6, #25
	str r4, [sp, #28]
	ldr r4, [sp, #4]
	add r2, r2, r7
	add r3, r3, r4
	ldr r11, [sp, #20]
	eor r11, r11, r2
	eor r14, r14, r3
	ror r11, r11, #16
	ror r14, r14, #16
	add r8, r8, r11
	add r9, r9, r14
	eor r7, r7, r8
	eor r4, r4, r9
	ror r7, r7, #20
	ror r4, r4, #20
	str r6, [sp, #8]
	add r2, r2, r7
	add r3, r3, r4
	eor r11, r11, r2
	eor r14, r14, r3
	ror r11, r11, #24
	ror r14, r14, #24
	add r8, r8, r11
	add r9, r9, r14
	eor r7, r7, r8
	eor r4, r4, r9
	ror r7, r7, #25
	ror r4, r4, #25
	bne .Lchacha_blocks_neon_rounds2
	str r8, [sp, #0]
	str r9, [sp, #4]
	str r10, [sp, #8]
	str r12, [sp, #16]
	str r11, [sp, #20]
	str r14, [sp, #24]
	ldr r12, [sp, #48]
	ldr r14, [sp, #40]
	ldr r8, [sp, #(64 +0)]
	ldr r9, [sp, #(64 +4)]
	ldr r10, [sp, #(64 +8)]
	ldr r11, [sp, #(64 +12)]
	add r0, r0, r8
	add r1, r1, r9
	add r2, r2, r10
	ldr r8, [sp, #(64 +16)]
	add r3, r3, r11
	ldr r9, [sp, #(64 +20)]
	add r4, r4, r8
	ldr r10, [sp, #(64 +24)]
	add r5, r5, r9
	ldr r11, [sp, #(64 +28)]
	add r6, r6, r10
	tst r12, r12
	add r7, r7, r11
	beq .Lchacha_blocks_neon_nomessage21
	UNALIGNED_LDMIA4(r12, r8, r9, r10, r11)
	tst r12, r12
	eor r0, r0, r8
	eor r1, r1, r9
	eor r2, r2, r10
	ldr r8, [r12, #0]
	eor r3, r3, r11
	ldr r9, [r12, #4]
	eor r4, r4, r8
	ldr r10, [r12, #8]
	eor r5, r5, r9
	ldr r11, [r12, #12]
	eor r6, r6, r10
	add r12, r12, #16
	eor r7, r7, r11
.Lchacha_blocks_neon_nomessage21:
	UNALIGNED_STMIA8(r14, r0, r1, r2, r3, r4, r5, r6, r7)
	ldm sp, {r0-r7}
	ldr r8, [sp, #(64 +32)]
	ldr r9, [sp, #(64 +36)]
	ldr r10, [sp, #(64 +40)]
	ldr r11, [sp, #(64 +44)]
	add r0, r0, r8
	add r1, r1, r9
	add r2, r2, r10
	ldr r8, [sp, #(64 +48)]
	add r3, r3, r11
	ldr r9, [sp, #(64 +52)]
	add r4, r4, r8
	ldr r10, [sp, #(64 +56)]
	add r5, r5, r9
	ldr r11, [sp, #(64 +60)]
	add r6, r6, r10
	adds r8, r8, #1
	add r7, r7, r11
	adc r9, r9, #0
	str r8, [sp, #(64 +48)]
	tst r12, r12
	str r9, [sp, #(64 +52)]
	beq .Lchacha_blocks_neon_nomessage22
	UNALIGNED_LDMIA4(r12, r8, r9, r10, r11)
	tst r12, r12
	eor r0, r0, r8
	eor r1, r1, r9
	eor r2, r2, r10
	ldr r8, [r12, #0]
	eor r3, r3, r11
	ldr r9, [r12, #4]
	eor r4, r4, r8
	ldr r10, [r12, #8]
	eor r5, r5, r9
	ldr r11, [r12, #12]
	eor r6, r6, r10
	add r12, r12, #16
	eor r7, r7, r11
.Lchacha_blocks_neon_nomessage22:
	UNALIGNED_STMIA8(r14, r0, r1, r2, r3, r4, r5, r6, r7)
	str r12, [sp, #48]
	str r14, [sp, #40]
	ldr r3, [sp, #52]
	cmp r3, #64
	sub r4, r3, #64
	str r4, [sp, #52]
	bhi .Lchacha_blocks_neon_mainloop2
	cmp r3, #64
	beq .Lchacha_blocks_neon_nocopy2
	ldr r1, [sp, #56]
	sub r14, r14, #64
.Lchacha_blocks_neon_copyinput2:
	subs r3, r3, #1
	ldrb r0, [r14], #1
	strb r0, [r1], #1
	bne .Lchacha_blocks_neon_copyinput2
.Lchacha_blocks_neon_nocopy2:
.Lchacha_blocks_neon_done:
	ldr r7, [sp, #60]
	ldr r8, [sp, #(64 +48)]
	ldr r9, [sp, #(64 +52)]
	str r8, [r7, #(48 + 0)]
	str r9, [r7, #(48 + 4)]
	mov r12, sp
	stmia r12!, {r0-r7}
	add r12, r12, #48
	stmia r12!, {r0-r7}
	sub r0, sp, #8
	ldr sp, [sp, #192]
	ldmfd sp!, {r4-r12, r14}
	vldm sp!, {q4-q7}
	sub r0, sp, r0
	bx lr
.Lchacha_blocks_neon_nobytes:
	mov r0, #0;
	bx lr
.ltorg
.size _gcry_chacha20_armv7_neon_blocks,.-_gcry_chacha20_armv7_neon_blocks;

#endif
