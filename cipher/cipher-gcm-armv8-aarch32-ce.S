/* cipher-gcm-armv8-aarch32-ce.S - ARM/CE accelerated GHASH
 * Copyright (C) 2016 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
    defined(HAVE_GCC_INLINE_ASM_AARCH32_CRYPTO)

.syntax unified
.fpu crypto-neon-fp-armv8
.arm

.text

#ifdef __PIC__
#  define GET_DATA_POINTER(reg, name, rtmp) \
		ldr reg, 1f; \
		ldr rtmp, 2f; \
		b 3f; \
	1:	.word _GLOBAL_OFFSET_TABLE_-(3f+8); \
	2:	.word name(GOT); \
	3:	add reg, pc, reg; \
		ldr reg, [reg, rtmp];
#else
#  define GET_DATA_POINTER(reg, name, rtmp) ldr reg, =name
#endif


/* Constants */

.align 4
gcry_gcm_reduction_constant:
.Lrconst64:
  .quad 0xc200000000000000


/* Register macros */

#define rhash q0
#define rhash_l d0
#define rhash_h d1

#define rbuf q1
#define rbuf_l d2
#define rbuf_h d3

#define rh0 q2
#define rh0_l d4
#define rh0_h d5

#define rt0 q3
#define rt0_l d6
#define rt0_h d7

#define rr0 q8
#define rr0_l d16
#define rr0_h d17

#define rr1 q9
#define rr1_l d18
#define rr1_h d19

#define rrconst q15
#define rrconst_l d30
#define rrconst_h d31

#define ia rbuf_h
#define ib rbuf_l
#define oa rh0_l
#define ob rh0_h
#define co rrconst_l
#define ma rrconst_h

/* GHASH macros */

/* See "Gouvêa, C. P. L. & López, J. Implementing GCM on ARMv8. Topics in
 * Cryptology — CT-RSA 2015" for details.
 */

/* Input: 'a' and 'b', Output: 'r0:r1' (low 128-bits in r0, high in r1) */
#define PMUL_128x128(r0, r1, a, b, t, interleave_op) \
        veor t##_h, b##_l, b##_h; \
        veor t##_l, a##_l, a##_h; \
        vmull.p64 r0, a##_l, b##_l; \
        vmull.p64 r1, a##_h, b##_h; \
        vmull.p64 t, t##_h, t##_l; \
        interleave_op(); \
        veor t, r0; \
        veor t, r1; \
        veor r0##_h, t##_l; \
        veor r1##_l, t##_h;

/* Input: 'r0:r1', Output: 'a' */
#define REDUCTION(a, r0, r1, rconst, t, interleave_op) \
        vmull.p64 t, r0##_l, rconst; \
        veor r0##_h, t##_l; \
        veor r1##_l, t##_h; \
        interleave_op(); \
        vmull.p64 t, r0##_h, rconst; \
        veor r1, t; \
        veor a, r0, r1;

#define _(...) /*_*/
#define vrev_rbuf() vrev64.8 rbuf, rbuf;
#define vext_rbuf() vext.8 rbuf, rbuf, rbuf, #8;

/* Other functional macros */

#define CLEAR_REG(reg) veor reg, reg;


/*
 * unsigned int _gcry_ghash_armv8_ce_pmull (void *gcm_key, byte *result,
 *                                          const byte *buf, size_t nblocks,
 *                                          void *gcm_table);
 */
.align 3
.globl _gcry_ghash_armv8_ce_pmull
.type  _gcry_ghash_armv8_ce_pmull,%function;
_gcry_ghash_armv8_ce_pmull:
  /* input:
   *    r0: gcm_key
   *    r1: result/hash
   *    r2: buf
   *    r3: nblocks
   *    %st+0: gcm_table
   */
  push {r4, lr}

  cmp r3, #0
  beq .Ldo_nothing

  GET_DATA_POINTER(lr, .Lrconst64, r4)

  subs r3, r3, #1
  vld1.64 {rhash}, [r1]
  vld1.64 {rh0}, [r0]

  vrev64.8 rhash, rhash /* byte-swap */
  vld1.64 {rrconst_h}, [lr]
  vext.8 rhash, rhash, rhash, #8

  vld1.64 {rbuf}, [r2]!

  vrev64.8 rbuf, rbuf /* byte-swap */
  vext.8 rbuf, rbuf, rbuf, #8

  veor rhash, rhash, rbuf

  beq .Lend

.Loop:
  vld1.64 {rbuf}, [r2]!
  subs r3, r3, #1
  PMUL_128x128(rr0, rr1, rh0, rhash, rt0, vrev_rbuf)
  REDUCTION(rhash, rr0, rr1, rrconst_h, rt0, vext_rbuf)
  veor rhash, rhash, rbuf

  bne .Loop

.Lend:
  PMUL_128x128(rr0, rr1, rh0, rhash, rt0, _)
  REDUCTION(rhash, rr0, rr1, rrconst_h, rt0, _)

  CLEAR_REG(rr1)
  CLEAR_REG(rr0)
  vrev64.8 rhash, rhash /* byte-swap */
  CLEAR_REG(rbuf)
  CLEAR_REG(rt0)
  vext.8 rhash, rhash, rhash, #8
  CLEAR_REG(rh0)

  vst1.64 {rhash}, [r1]
  CLEAR_REG(rhash)

.Ldo_nothing:
  mov r0, #0
  pop {r4, pc}
.size _gcry_ghash_armv8_ce_pmull,.-_gcry_ghash_armv8_ce_pmull;


/*
 * void _gcry_ghash_setup_armv8_ce_pmull (void *gcm_key, void *gcm_table);
 */
.align 3
.globl _gcry_ghash_setup_armv8_ce_pmull
.type  _gcry_ghash_setup_armv8_ce_pmull,%function;
_gcry_ghash_setup_armv8_ce_pmull:
  /* input:
   *	r0: gcm_key
   *	r1: gcm_table
   */

  push {r4, lr}

  GET_DATA_POINTER(r4, .Lrconst64, lr)

  /* H <<< 1 */
  vld1.64 {ib,ia}, [r0]
  vld1.64 {co}, [r4]
  vrev64.8 ib, ib;
  vrev64.8 ia, ia;
  vshr.s64 ma, ib, #63
  vshr.u64 oa, ib, #63
  vshr.u64 ob, ia, #63
  vand ma, co
  vshl.u64 ib, ib, #1
  vshl.u64 ia, ia, #1
  vorr ob, ib
  vorr oa, ia
  veor ob, ma

  vst1.64 {oa, ob}, [r0]

  pop {r4, pc}
.size _gcry_ghash_setup_armv8_ce_pmull,.-_gcry_ghash_setup_armv8_ce_pmull;

#endif
