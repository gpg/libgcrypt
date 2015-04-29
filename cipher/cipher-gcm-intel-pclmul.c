/* cipher-gcm-intel-pclmul.c  -  Intel PCLMUL accelerated Galois Counter Mode
 *                               implementation
 * Copyright (C) 2013-2014 Jussi Kivilinna <jussi.kivilinna@iki.fi>
 *
 * This file is part of Libgcrypt.
 *
 * Libgcrypt is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser general Public License as
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "./cipher-internal.h"


#ifdef GCM_USE_INTEL_PCLMUL


#if _GCRY_GCC_VERSION >= 40400 /* 4.4 */
/* Prevent compiler from issuing SSE instructions between asm blocks. */
#  pragma GCC target("no-sse")
#endif


/*
 Intel PCLMUL ghash based on white paper:
  "Intel® Carry-Less Multiplication Instruction and its Usage for Computing the
   GCM Mode - Rev 2.01"; Shay Gueron, Michael E. Kounavis.
 */
static inline void gfmul_pclmul(void)
{
  /* Input: XMM0 and XMM1, Output: XMM1. Input XMM0 stays unmodified.
     Input must be converted to little-endian.
   */
  asm volatile (/* gfmul, xmm0 has operator a and xmm1 has operator b. */
                "pshufd $78, %%xmm0, %%xmm2\n\t"
                "pshufd $78, %%xmm1, %%xmm4\n\t"
                "pxor %%xmm0, %%xmm2\n\t" /* xmm2 holds a0+a1 */
                "pxor %%xmm1, %%xmm4\n\t" /* xmm4 holds b0+b1 */

                "movdqa %%xmm0, %%xmm3\n\t"
                "pclmulqdq $0, %%xmm1, %%xmm3\n\t"  /* xmm3 holds a0*b0 */
                "movdqa %%xmm0, %%xmm6\n\t"
                "pclmulqdq $17, %%xmm1, %%xmm6\n\t" /* xmm6 holds a1*b1 */
                "movdqa %%xmm3, %%xmm5\n\t"
                "pclmulqdq $0, %%xmm2, %%xmm4\n\t"  /* xmm4 holds (a0+a1)*(b0+b1) */

                "pxor %%xmm6, %%xmm5\n\t" /* xmm5 holds a0*b0+a1*b1 */
                "pxor %%xmm5, %%xmm4\n\t" /* xmm4 holds a0*b0+a1*b1+(a0+a1)*(b0+b1) */
                "movdqa %%xmm4, %%xmm5\n\t"
                "psrldq $8, %%xmm4\n\t"
                "pslldq $8, %%xmm5\n\t"
                "pxor %%xmm5, %%xmm3\n\t"
                "pxor %%xmm4, %%xmm6\n\t" /* <xmm6:xmm3> holds the result of the
                                             carry-less multiplication of xmm0
                                             by xmm1 */

                /* shift the result by one bit position to the left cope for
                   the fact that bits are reversed */
                "movdqa %%xmm3, %%xmm4\n\t"
                "movdqa %%xmm6, %%xmm5\n\t"
                "pslld $1, %%xmm3\n\t"
                "pslld $1, %%xmm6\n\t"
                "psrld $31, %%xmm4\n\t"
                "psrld $31, %%xmm5\n\t"
                "movdqa %%xmm4, %%xmm1\n\t"
                "pslldq $4, %%xmm5\n\t"
                "pslldq $4, %%xmm4\n\t"
                "psrldq $12, %%xmm1\n\t"
                "por %%xmm4, %%xmm3\n\t"
                "por %%xmm5, %%xmm6\n\t"
                "por %%xmm6, %%xmm1\n\t"

                /* first phase of the reduction */
                "movdqa %%xmm3, %%xmm6\n\t"
                "movdqa %%xmm3, %%xmm7\n\t"
                "pslld $31, %%xmm6\n\t"  /* packed right shifting << 31 */
                "movdqa %%xmm3, %%xmm5\n\t"
                "pslld $30, %%xmm7\n\t"  /* packed right shifting shift << 30 */
                "pslld $25, %%xmm5\n\t"  /* packed right shifting shift << 25 */
                "pxor %%xmm7, %%xmm6\n\t" /* xor the shifted versions */
                "pxor %%xmm5, %%xmm6\n\t"
                "movdqa %%xmm6, %%xmm7\n\t"
                "pslldq $12, %%xmm6\n\t"
                "psrldq $4, %%xmm7\n\t"
                "pxor %%xmm6, %%xmm3\n\t" /* first phase of the reduction
                                             complete */

                /* second phase of the reduction */
                "movdqa %%xmm3, %%xmm2\n\t"
                "movdqa %%xmm3, %%xmm4\n\t"
                "psrld $1, %%xmm2\n\t"    /* packed left shifting >> 1 */
                "movdqa %%xmm3, %%xmm5\n\t"
                "psrld $2, %%xmm4\n\t"    /* packed left shifting >> 2 */
                "psrld $7, %%xmm5\n\t"    /* packed left shifting >> 7 */
                "pxor %%xmm4, %%xmm2\n\t" /* xor the shifted versions */
                "pxor %%xmm5, %%xmm2\n\t"
                "pxor %%xmm7, %%xmm2\n\t"
                "pxor %%xmm2, %%xmm3\n\t"
                "pxor %%xmm3, %%xmm1\n\t" /* the result is in xmm1 */
                ::: "cc" );
}


#ifdef __x86_64__
static inline void gfmul_pclmul_aggr4(void)
{
  /* Input:
      H¹: XMM0          X_i            : XMM6
      H²: XMM8          X_(i-1)        : XMM3
      H³: XMM9          X_(i-2)        : XMM2
      H⁴: XMM10         X_(i-3)⊕Y_(i-4): XMM1
     Output:
      Y_i: XMM1
     Inputs XMM0 stays unmodified.
     Input must be converted to little-endian.
   */
  asm volatile (/* perform clmul and merge results... */
                "pshufd $78, %%xmm10, %%xmm11\n\t"
                "pshufd $78, %%xmm1, %%xmm12\n\t"
                "pxor %%xmm10, %%xmm11\n\t" /* xmm11 holds 4:a0+a1 */
                "pxor %%xmm1, %%xmm12\n\t" /* xmm12 holds 4:b0+b1 */

                "pshufd $78, %%xmm9, %%xmm13\n\t"
                "pshufd $78, %%xmm2, %%xmm14\n\t"
                "pxor %%xmm9, %%xmm13\n\t" /* xmm13 holds 3:a0+a1 */
                "pxor %%xmm2, %%xmm14\n\t" /* xmm14 holds 3:b0+b1 */

                "pshufd $78, %%xmm8, %%xmm5\n\t"
                "pshufd $78, %%xmm3, %%xmm15\n\t"
                "pxor %%xmm8, %%xmm5\n\t" /* xmm1 holds 2:a0+a1 */
                "pxor %%xmm3, %%xmm15\n\t" /* xmm2 holds 2:b0+b1 */

                "movdqa %%xmm10, %%xmm4\n\t"
                "movdqa %%xmm9, %%xmm7\n\t"
                "pclmulqdq $0, %%xmm1, %%xmm4\n\t"   /* xmm4 holds 4:a0*b0 */
                "pclmulqdq $0, %%xmm2, %%xmm7\n\t"   /* xmm7 holds 3:a0*b0 */
                "pclmulqdq $17, %%xmm10, %%xmm1\n\t" /* xmm1 holds 4:a1*b1 */
                "pclmulqdq $17, %%xmm9, %%xmm2\n\t"  /* xmm9 holds 3:a1*b1 */
                "pclmulqdq $0, %%xmm11, %%xmm12\n\t" /* xmm12 holds 4:(a0+a1)*(b0+b1) */
                "pclmulqdq $0, %%xmm13, %%xmm14\n\t" /* xmm14 holds 3:(a0+a1)*(b0+b1) */

                "pshufd $78, %%xmm0, %%xmm10\n\t"
                "pshufd $78, %%xmm6, %%xmm11\n\t"
                "pxor %%xmm0, %%xmm10\n\t" /* xmm10 holds 1:a0+a1 */
                "pxor %%xmm6, %%xmm11\n\t" /* xmm11 holds 1:b0+b1 */

                "pxor %%xmm4, %%xmm7\n\t"   /* xmm7 holds 3+4:a0*b0 */
                "pxor %%xmm2, %%xmm1\n\t"   /* xmm1 holds 3+4:a1*b1 */
                "pxor %%xmm14, %%xmm12\n\t" /* xmm12 holds 3+4:(a0+a1)*(b0+b1) */

                "movdqa %%xmm8, %%xmm13\n\t"
                "pclmulqdq $0, %%xmm3, %%xmm13\n\t"  /* xmm13 holds 2:a0*b0 */
                "pclmulqdq $17, %%xmm8, %%xmm3\n\t"  /* xmm3 holds 2:a1*b1 */
                "pclmulqdq $0, %%xmm5, %%xmm15\n\t" /* xmm15 holds 2:(a0+a1)*(b0+b1) */

                "pxor %%xmm13, %%xmm7\n\t" /* xmm7 holds 2+3+4:a0*b0 */
                "pxor %%xmm3, %%xmm1\n\t"  /* xmm1 holds 2+3+4:a1*b1 */
                "pxor %%xmm15, %%xmm12\n\t" /* xmm12 holds 2+3+4:(a0+a1)*(b0+b1) */

                "movdqa %%xmm0, %%xmm3\n\t"
                "pclmulqdq $0, %%xmm6, %%xmm3\n\t"  /* xmm3 holds 1:a0*b0 */
                "pclmulqdq $17, %%xmm0, %%xmm6\n\t" /* xmm6 holds 1:a1*b1 */
                "movdqa %%xmm11, %%xmm4\n\t"
                "pclmulqdq $0, %%xmm10, %%xmm4\n\t" /* xmm4 holds 1:(a0+a1)*(b0+b1) */

                "pxor %%xmm7, %%xmm3\n\t"  /* xmm3 holds 1+2+3+4:a0*b0 */
                "pxor %%xmm1, %%xmm6\n\t"  /* xmm6 holds 1+2+3+4:a1*b1 */
                "pxor %%xmm12, %%xmm4\n\t" /* xmm4 holds 1+2+3+4:(a0+a1)*(b0+b1) */

                /* aggregated reduction... */
                "movdqa %%xmm3, %%xmm5\n\t"
                "pxor %%xmm6, %%xmm5\n\t" /* xmm5 holds a0*b0+a1*b1 */
                "pxor %%xmm5, %%xmm4\n\t" /* xmm4 holds a0*b0+a1*b1+(a0+a1)*(b0+b1) */
                "movdqa %%xmm4, %%xmm5\n\t"
                "psrldq $8, %%xmm4\n\t"
                "pslldq $8, %%xmm5\n\t"
                "pxor %%xmm5, %%xmm3\n\t"
                "pxor %%xmm4, %%xmm6\n\t" /* <xmm6:xmm3> holds the result of the
                                             carry-less multiplication of xmm0
                                             by xmm1 */

                /* shift the result by one bit position to the left cope for
                   the fact that bits are reversed */
                "movdqa %%xmm3, %%xmm4\n\t"
                "movdqa %%xmm6, %%xmm5\n\t"
                "pslld $1, %%xmm3\n\t"
                "pslld $1, %%xmm6\n\t"
                "psrld $31, %%xmm4\n\t"
                "psrld $31, %%xmm5\n\t"
                "movdqa %%xmm4, %%xmm1\n\t"
                "pslldq $4, %%xmm5\n\t"
                "pslldq $4, %%xmm4\n\t"
                "psrldq $12, %%xmm1\n\t"
                "por %%xmm4, %%xmm3\n\t"
                "por %%xmm5, %%xmm6\n\t"
                "por %%xmm6, %%xmm1\n\t"

                /* first phase of the reduction */
                "movdqa %%xmm3, %%xmm6\n\t"
                "movdqa %%xmm3, %%xmm7\n\t"
                "pslld $31, %%xmm6\n\t"  /* packed right shifting << 31 */
                "movdqa %%xmm3, %%xmm5\n\t"
                "pslld $30, %%xmm7\n\t"  /* packed right shifting shift << 30 */
                "pslld $25, %%xmm5\n\t"  /* packed right shifting shift << 25 */
                "pxor %%xmm7, %%xmm6\n\t" /* xor the shifted versions */
                "pxor %%xmm5, %%xmm6\n\t"
                "movdqa %%xmm6, %%xmm7\n\t"
                "pslldq $12, %%xmm6\n\t"
                "psrldq $4, %%xmm7\n\t"
                "pxor %%xmm6, %%xmm3\n\t" /* first phase of the reduction
                                             complete */

                /* second phase of the reduction */
                "movdqa %%xmm3, %%xmm2\n\t"
                "movdqa %%xmm3, %%xmm4\n\t"
                "psrld $1, %%xmm2\n\t"    /* packed left shifting >> 1 */
                "movdqa %%xmm3, %%xmm5\n\t"
                "psrld $2, %%xmm4\n\t"    /* packed left shifting >> 2 */
                "psrld $7, %%xmm5\n\t"    /* packed left shifting >> 7 */
                "pxor %%xmm4, %%xmm2\n\t" /* xor the shifted versions */
                "pxor %%xmm5, %%xmm2\n\t"
                "pxor %%xmm7, %%xmm2\n\t"
                "pxor %%xmm2, %%xmm3\n\t"
                "pxor %%xmm3, %%xmm1\n\t" /* the result is in xmm1 */
                :::"cc");
}
#endif


void
_gcry_ghash_setup_intel_pclmul (gcry_cipher_hd_t c)
{
  u64 tmp[2];
#if defined(__x86_64__) && defined(__WIN64__)
  char win64tmp[3 * 16];

  /* XMM6-XMM8 need to be restored after use. */
  asm volatile ("movdqu %%xmm6, 0*16(%0)\n\t"
                "movdqu %%xmm7, 1*16(%0)\n\t"
                "movdqu %%xmm8, 2*16(%0)\n\t"
                :
                : "r" (win64tmp)
                : "memory");
#endif

  /* Swap endianness of hsub. */
  tmp[0] = buf_get_be64(c->u_mode.gcm.u_ghash_key.key + 8);
  tmp[1] = buf_get_be64(c->u_mode.gcm.u_ghash_key.key + 0);
  buf_cpy (c->u_mode.gcm.u_ghash_key.key, tmp, GCRY_GCM_BLOCK_LEN);

#ifdef __x86_64__
  asm volatile ("movdqu %[h_1], %%xmm0\n\t"
                "movdqa %%xmm0, %%xmm1\n\t"
                :
                : [h_1] "m" (*tmp));

  gfmul_pclmul (); /* H•H => H² */

  asm volatile ("movdqu %%xmm1, 0*16(%[h_234])\n\t"
                "movdqa %%xmm1, %%xmm8\n\t"
                :
                : [h_234] "r" (c->u_mode.gcm.gcm_table)
                : "memory");

  gfmul_pclmul (); /* H•H² => H³ */

  asm volatile ("movdqa %%xmm8, %%xmm0\n\t"
                "movdqu %%xmm1, 1*16(%[h_234])\n\t"
                "movdqa %%xmm8, %%xmm1\n\t"
                :
                : [h_234] "r" (c->u_mode.gcm.gcm_table)
                : "memory");

  gfmul_pclmul (); /* H²•H² => H⁴ */

  asm volatile ("movdqu %%xmm1, 2*16(%[h_234])\n\t"
                :
                : [h_234] "r" (c->u_mode.gcm.gcm_table)
                : "memory");

#ifdef __WIN64__
  /* Clear/restore used registers. */
  asm volatile( "pxor %%xmm0, %%xmm0\n\t"
                "pxor %%xmm1, %%xmm1\n\t"
                "pxor %%xmm2, %%xmm2\n\t"
                "pxor %%xmm3, %%xmm3\n\t"
                "pxor %%xmm4, %%xmm4\n\t"
                "pxor %%xmm5, %%xmm5\n\t"
                "movdqu 0*16(%0), %%xmm6\n\t"
                "movdqu 1*16(%0), %%xmm7\n\t"
                "movdqu 2*16(%0), %%xmm8\n\t"
                :
                : "r" (win64tmp)
                : "memory");
#else
  /* Clear used registers. */
  asm volatile( "pxor %%xmm0, %%xmm0\n\t"
                "pxor %%xmm1, %%xmm1\n\t"
                "pxor %%xmm2, %%xmm2\n\t"
                "pxor %%xmm3, %%xmm3\n\t"
                "pxor %%xmm4, %%xmm4\n\t"
                "pxor %%xmm5, %%xmm5\n\t"
                "pxor %%xmm6, %%xmm6\n\t"
                "pxor %%xmm7, %%xmm7\n\t"
                "pxor %%xmm8, %%xmm8\n\t"
                ::: "cc" );
#endif
#endif

  wipememory (tmp, sizeof(tmp));
}


unsigned int
_gcry_ghash_intel_pclmul (gcry_cipher_hd_t c, byte *result, const byte *buf,
                          size_t nblocks)
{
  static const unsigned char be_mask[16] __attribute__ ((aligned (16))) =
    { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  const unsigned int blocksize = GCRY_GCM_BLOCK_LEN;
#ifdef __WIN64__
  char win64tmp[10 * 16];
#endif

  if (nblocks == 0)
    return 0;

#ifdef __WIN64__
  /* XMM8-XMM15 need to be restored after use. */
  asm volatile ("movdqu %%xmm6,  0*16(%0)\n\t"
                "movdqu %%xmm7,  1*16(%0)\n\t"
                "movdqu %%xmm8,  2*16(%0)\n\t"
                "movdqu %%xmm9,  3*16(%0)\n\t"
                "movdqu %%xmm10, 4*16(%0)\n\t"
                "movdqu %%xmm11, 5*16(%0)\n\t"
                "movdqu %%xmm12, 6*16(%0)\n\t"
                "movdqu %%xmm13, 7*16(%0)\n\t"
                "movdqu %%xmm14, 8*16(%0)\n\t"
                "movdqu %%xmm15, 9*16(%0)\n\t"
                :
                : "r" (win64tmp)
                : "memory" );
#endif

  /* Preload hash and H1. */
  asm volatile ("movdqu %[hash], %%xmm1\n\t"
                "movdqa %[hsub], %%xmm0\n\t"
                "pshufb %[be_mask], %%xmm1\n\t" /* be => le */
                :
                : [hash] "m" (*result), [be_mask] "m" (*be_mask),
                  [hsub] "m" (*c->u_mode.gcm.u_ghash_key.key));

#ifdef __x86_64__
  if (nblocks >= 4)
    {
      do
        {
          asm volatile ("movdqa %[be_mask], %%xmm4\n\t"
                        "movdqu 0*16(%[buf]), %%xmm5\n\t"
                        "movdqu 1*16(%[buf]), %%xmm2\n\t"
                        "movdqu 2*16(%[buf]), %%xmm3\n\t"
                        "movdqu 3*16(%[buf]), %%xmm6\n\t"
                        "pshufb %%xmm4, %%xmm5\n\t" /* be => le */

                        /* Load H2, H3, H4. */
                        "movdqu 2*16(%[h_234]), %%xmm10\n\t"
                        "movdqu 1*16(%[h_234]), %%xmm9\n\t"
                        "movdqu 0*16(%[h_234]), %%xmm8\n\t"

                        "pxor %%xmm5, %%xmm1\n\t"
                        "pshufb %%xmm4, %%xmm2\n\t" /* be => le */
                        "pshufb %%xmm4, %%xmm3\n\t" /* be => le */
                        "pshufb %%xmm4, %%xmm6\n\t" /* be => le */
                        :
                        : [buf] "r" (buf), [be_mask] "m" (*be_mask),
                          [h_234] "r" (c->u_mode.gcm.gcm_table));

          gfmul_pclmul_aggr4 ();

          buf += 4 * blocksize;
          nblocks -= 4;
        }
      while (nblocks >= 4);

#ifndef __WIN64__
      /* Clear used x86-64/XMM registers. */
      asm volatile( "pxor %%xmm8, %%xmm8\n\t"
                    "pxor %%xmm9, %%xmm9\n\t"
                    "pxor %%xmm10, %%xmm10\n\t"
                    "pxor %%xmm11, %%xmm11\n\t"
                    "pxor %%xmm12, %%xmm12\n\t"
                    "pxor %%xmm13, %%xmm13\n\t"
                    "pxor %%xmm14, %%xmm14\n\t"
                    "pxor %%xmm15, %%xmm15\n\t"
                    ::: "cc" );
#endif
    }
#endif

  while (nblocks--)
    {
      asm volatile ("movdqu %[buf], %%xmm2\n\t"
                    "pshufb %[be_mask], %%xmm2\n\t" /* be => le */
                    "pxor %%xmm2, %%xmm1\n\t"
                    :
                    : [buf] "m" (*buf), [be_mask] "m" (*be_mask));

      gfmul_pclmul ();

      buf += blocksize;
    }

  /* Store hash. */
  asm volatile ("pshufb %[be_mask], %%xmm1\n\t" /* be => le */
                "movdqu %%xmm1, %[hash]\n\t"
                : [hash] "=m" (*result)
                : [be_mask] "m" (*be_mask));

#ifdef __WIN64__
  /* Clear/restore used registers. */
  asm volatile( "pxor %%xmm0, %%xmm0\n\t"
                "pxor %%xmm1, %%xmm1\n\t"
                "pxor %%xmm2, %%xmm2\n\t"
                "pxor %%xmm3, %%xmm3\n\t"
                "pxor %%xmm4, %%xmm4\n\t"
                "pxor %%xmm5, %%xmm5\n\t"
                "movdqu 0*16(%0), %%xmm6\n\t"
                "movdqu 1*16(%0), %%xmm7\n\t"
                "movdqu 2*16(%0), %%xmm8\n\t"
                "movdqu 3*16(%0), %%xmm9\n\t"
                "movdqu 4*16(%0), %%xmm10\n\t"
                "movdqu 5*16(%0), %%xmm11\n\t"
                "movdqu 6*16(%0), %%xmm12\n\t"
                "movdqu 7*16(%0), %%xmm13\n\t"
                "movdqu 8*16(%0), %%xmm14\n\t"
                "movdqu 9*16(%0), %%xmm15\n\t"
                :
                : "r" (win64tmp)
                : "memory" );
#else
  /* Clear used registers. */
  asm volatile( "pxor %%xmm0, %%xmm0\n\t"
                "pxor %%xmm1, %%xmm1\n\t"
                "pxor %%xmm2, %%xmm2\n\t"
                "pxor %%xmm3, %%xmm3\n\t"
                "pxor %%xmm4, %%xmm4\n\t"
                "pxor %%xmm5, %%xmm5\n\t"
                "pxor %%xmm6, %%xmm6\n\t"
                "pxor %%xmm7, %%xmm7\n\t"
                ::: "cc" );
#endif

  return 0;
}

#endif /* GCM_USE_INTEL_PCLMUL */
