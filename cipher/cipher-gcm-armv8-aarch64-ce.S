/* cipher-gcm-armv8-aarch64-ce.S - ARM/CE accelerated GHASH
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

#if defined(__AARCH64EL__) && \
    defined(HAVE_COMPATIBLE_GCC_AARCH64_PLATFORM_AS) && \
    defined(HAVE_GCC_INLINE_ASM_AARCH64_CRYPTO)

.arch armv8-a+crypto

.text

#define GET_DATA_POINTER(reg, name) \
		adrp    reg, :got:name ; \
		ldr     reg, [reg, #:got_lo12:name] ;


/* Constants */

.align 4
gcry_gcm_reduction_constant:
.Lrconst:
  .quad 0x87


/* Register macros */

#define rhash   v0
#define rbuf    v1
#define rh0     v2
#define rr0     v3
#define rr1     v4
#define rrconst v5
#define vT0     v16
#define vT1     v17
#define vZZ     v18

/* GHASH macros */

/* See "Gouvêa, C. P. L. & López, J. Implementing GCM on ARMv8. Topics in
 * Cryptology — CT-RSA 2015" for details.
 */

/* Input: 'a' and 'b', Output: 'r0:r1' (low 128-bits in r0, high in r1) */
#define PMUL_128x128(r0, r1, a, b, interleave_op) \
	ext vT0.16b, b.16b, b.16b, #8; \
	pmull r0.1q, a.1d, b.1d; \
	pmull2 r1.1q, a.2d, b.2d; \
	pmull vT1.1q, a.1d, vT0.1d; \
	pmull2 vT0.1q, a.2d, vT0.2d; \
	interleave_op(); \
	eor vT0.16b, vT0.16b, vT1.16b; \
	ext vT1.16b, vZZ.16b, vT0.16b, #8; \
	ext vT0.16b, vT0.16b, vZZ.16b, #8; \
	eor r0.16b, r0.16b, vT1.16b; \
	eor r1.16b, r1.16b, vT0.16b;

/* Input: 'r0:r1', Output: 'a' */
#define REDUCTION(a, r0, r1, rconst, interleave_op) \
        pmull2 vT0.1q, r1.2d, rconst.2d; \
        interleave_op(); \
        ext vT1.16b, vT0.16b, vZZ.16b, #8; \
        ext vT0.16b, vZZ.16b, vT0.16b, #8; \
        eor r1.16b, r1.16b, vT1.16b; \
        eor r0.16b, r0.16b, vT0.16b; \
        pmull vT0.1q, r1.1d, rconst.1d; \
        eor a.16b, r0.16b, vT0.16b;

#define _(...) /*_*/
#define ld1_rbuf()  ld1 {rbuf.16b}, [x2], #16;
#define rbit_rbuf() rbit rbuf.16b, rbuf.16b;

/* Other functional macros */

#define CLEAR_REG(reg) eor reg.16b, reg.16b, reg.16b;


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
   *    x0: gcm_key
   *    x1: result/hash
   *    x2: buf
   *    x3: nblocks
   *    x4: gcm_table
   */
  cbz x3, .Ldo_nothing;

  GET_DATA_POINTER(x5, .Lrconst)

  sub x3, x3, #1

  eor vZZ.16b, vZZ.16b, vZZ.16b
  ld1 {rhash.16b}, [x1]
  ld1 {rh0.16b}, [x0]

  rbit rhash.16b, rhash.16b /* bit-swap */
  ld1r {rrconst.2d}, [x5]

  ld1 {rbuf.16b}, [x2], #16

  rbit rbuf.16b, rbuf.16b /* bit-swap */

  eor rhash.16b, rhash.16b, rbuf.16b

  cbz x3, .Lend

.Loop:
  PMUL_128x128(rr0, rr1, rh0, rhash, ld1_rbuf)
  sub x3, x3, #1
  REDUCTION(rhash, rr0, rr1, rrconst, rbit_rbuf)
  eor rhash.16b, rhash.16b, rbuf.16b

  cbnz x3, .Loop

.Lend:
  PMUL_128x128(rr0, rr1, rh0, rhash, _)
  REDUCTION(rhash, rr0, rr1, rrconst, _)

  CLEAR_REG(rr1)
  CLEAR_REG(rr0)
  rbit rhash.16b, rhash.16b /* bit-swap */
  CLEAR_REG(rbuf)
  CLEAR_REG(vT0)
  CLEAR_REG(vT1)
  CLEAR_REG(rh0)

  st1 {rhash.2d}, [x1]
  CLEAR_REG(rhash)

.Ldo_nothing:
  mov x0, #0
  ret
.size _gcry_ghash_armv8_ce_pmull,.-_gcry_ghash_armv8_ce_pmull;


/*
 * void _gcry_ghash_setup_armv8_ce_pmull (void *gcm_key, void *gcm_table);
 */
.align 3
.globl _gcry_ghash_setup_armv8_ce_pmull
.type  _gcry_ghash_setup_armv8_ce_pmull,%function;
_gcry_ghash_setup_armv8_ce_pmull:
  /* input:
   *	x0: gcm_key
   *	x1: gcm_table
   */

  ld1 {vT0.16b}, [x0]
  rbit vT0.16b, vT0.16b
  st1 {vT0.16b}, [x0]

  ret
.size _gcry_ghash_setup_armv8_ce_pmull,.-_gcry_ghash_setup_armv8_ce_pmull;

#endif
