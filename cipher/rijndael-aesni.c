/* AES-NI accelerated AES for Libgcrypt
 * Copyright (C) 2000, 2001, 2002, 2003, 2007,
 *               2008, 2011, 2012 Free Software Foundation, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h> /* for memcmp() */

#include "types.h"  /* for byte and u32 typedefs */
#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"
#include "cipher-selftest.h"
#include "rijndael-internal.h"
#include "./cipher-internal.h"


#ifdef USE_AESNI


#if _GCRY_GCC_VERSION >= 40400 /* 4.4 */
/* Prevent compiler from issuing SSE instructions between asm blocks. */
#  pragma GCC target("no-sse")
#endif


typedef struct u128_s
{
  u32 a, b, c, d;
} __attribute__((packed, aligned(1), may_alias)) u128_t;


/* Two macros to be called prior and after the use of AESNI
   instructions.  There should be no external function calls between
   the use of these macros.  There purpose is to make sure that the
   SSE regsiters are cleared and won't reveal any information about
   the key or the data.  */
#ifdef __WIN64__
/* XMM6-XMM15 are callee-saved registers on WIN64. */
# define aesni_prepare_2_6_variable char win64tmp[16]
# define aesni_prepare_7_15_variable char win64tmp7_15[16 * 9]
# define aesni_prepare() do { } while (0)
# define aesni_prepare_2_6()                                            \
   do { asm volatile ("movdqu %%xmm6, %0\n\t"                           \
                      : "=m" (*win64tmp)                                \
                      :                                                 \
                      : "memory");                                      \
   } while (0)
# define aesni_prepare_7_15()                                           \
   do { asm volatile ("movdqu %%xmm7,  0*16(%0)\n\t"                    \
                      "movdqu %%xmm8,  1*16(%0)\n\t"                    \
                      "movdqu %%xmm9,  2*16(%0)\n\t"                    \
                      "movdqu %%xmm10, 3*16(%0)\n\t"                    \
                      "movdqu %%xmm11, 4*16(%0)\n\t"                    \
                      "movdqu %%xmm12, 5*16(%0)\n\t"                    \
                      "movdqu %%xmm13, 6*16(%0)\n\t"                    \
                      "movdqu %%xmm14, 7*16(%0)\n\t"                    \
                      "movdqu %%xmm15, 8*16(%0)\n\t"                    \
                      :                                                 \
                      : "r" (win64tmp7_15)                              \
                      : "memory");                                      \
   } while (0)
# define aesni_cleanup()                                                \
   do { asm volatile ("pxor %%xmm0, %%xmm0\n\t"                         \
                      "pxor %%xmm1, %%xmm1\n" :: );                     \
   } while (0)
# define aesni_cleanup_2_6()                                            \
   do { asm volatile ("movdqu %0,   %%xmm6\n\t"                         \
                      "pxor %%xmm2, %%xmm2\n"                           \
                      "pxor %%xmm3, %%xmm3\n"                           \
                      "pxor %%xmm4, %%xmm4\n"                           \
                      "pxor %%xmm5, %%xmm5\n"                           \
                      :                                                 \
                      : "m" (*win64tmp)                                 \
                      : "memory");                                      \
   } while (0)
# define aesni_cleanup_7_15()                                           \
   do { asm volatile ("movdqu 0*16(%0), %%xmm7\n\t"                     \
                      "movdqu 1*16(%0), %%xmm8\n\t"                     \
                      "movdqu 2*16(%0), %%xmm9\n\t"                     \
                      "movdqu 3*16(%0), %%xmm10\n\t"                    \
                      "movdqu 4*16(%0), %%xmm11\n\t"                    \
                      "movdqu 5*16(%0), %%xmm12\n\t"                    \
                      "movdqu 6*16(%0), %%xmm13\n\t"                    \
                      "movdqu 7*16(%0), %%xmm14\n\t"                    \
                      "movdqu 8*16(%0), %%xmm15\n\t"                    \
                      :                                                 \
                      : "r" (win64tmp7_15)                              \
                      : "memory");                                      \
   } while (0)
#else
# define aesni_prepare_2_6_variable
# define aesni_prepare() do { } while (0)
# define aesni_prepare_2_6() do { } while (0)
# define aesni_cleanup()                                                \
   do { asm volatile ("pxor %%xmm0, %%xmm0\n\t"                         \
                      "pxor %%xmm1, %%xmm1\n" :: );                     \
   } while (0)
# define aesni_cleanup_2_6()                                            \
   do { asm volatile ("pxor %%xmm2, %%xmm2\n\t"                         \
                      "pxor %%xmm3, %%xmm3\n"                           \
                      "pxor %%xmm4, %%xmm4\n"                           \
                      "pxor %%xmm5, %%xmm5\n"                           \
                      "pxor %%xmm6, %%xmm6\n":: );                      \
   } while (0)
# ifdef __x86_64__
#  define aesni_prepare_7_15_variable
#  define aesni_prepare_7_15() do { } while (0)
#  define aesni_cleanup_7_15()                                          \
   do { asm volatile ("pxor %%xmm7, %%xmm7\n\t"                         \
                      "pxor %%xmm8, %%xmm8\n"                           \
                      "pxor %%xmm9, %%xmm9\n"                           \
                      "pxor %%xmm10, %%xmm10\n"                         \
                      "pxor %%xmm11, %%xmm11\n"                         \
                      "pxor %%xmm12, %%xmm12\n"                         \
                      "pxor %%xmm13, %%xmm13\n"                         \
                      "pxor %%xmm14, %%xmm14\n"                         \
                      "pxor %%xmm15, %%xmm15\n":: );                    \
   } while (0)
# endif
#endif

void
_gcry_aes_aesni_do_setkey (RIJNDAEL_context *ctx, const byte *key)
{
  aesni_prepare_2_6_variable;

  aesni_prepare();
  aesni_prepare_2_6();

  if (ctx->rounds < 12)
    {
      /* 128-bit key */
#define AESKEYGENASSIST_xmm1_xmm2(imm8) \
	".byte 0x66, 0x0f, 0x3a, 0xdf, 0xd1, " #imm8 " \n\t"
#define AESKEY_EXPAND128 \
	"pshufd $0xff, %%xmm2, %%xmm2\n\t" \
	"movdqa %%xmm1, %%xmm3\n\t" \
	"pslldq $4, %%xmm3\n\t" \
	"pxor   %%xmm3, %%xmm1\n\t" \
	"pslldq $4, %%xmm3\n\t" \
	"pxor   %%xmm3, %%xmm1\n\t" \
	"pslldq $4, %%xmm3\n\t" \
	"pxor   %%xmm3, %%xmm2\n\t" \
	"pxor   %%xmm2, %%xmm1\n\t"

      asm volatile ("movdqu (%[key]), %%xmm1\n\t"     /* xmm1 := key   */
                    "movdqa %%xmm1, (%[ksch])\n\t"     /* ksch[0] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x01)
                    AESKEY_EXPAND128
                    "movdqa %%xmm1, 0x10(%[ksch])\n\t" /* ksch[1] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x02)
                    AESKEY_EXPAND128
                    "movdqa %%xmm1, 0x20(%[ksch])\n\t" /* ksch[2] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x04)
                    AESKEY_EXPAND128
                    "movdqa %%xmm1, 0x30(%[ksch])\n\t" /* ksch[3] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x08)
                    AESKEY_EXPAND128
                    "movdqa %%xmm1, 0x40(%[ksch])\n\t" /* ksch[4] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x10)
                    AESKEY_EXPAND128
                    "movdqa %%xmm1, 0x50(%[ksch])\n\t" /* ksch[5] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x20)
                    AESKEY_EXPAND128
                    "movdqa %%xmm1, 0x60(%[ksch])\n\t" /* ksch[6] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x40)
                    AESKEY_EXPAND128
                    "movdqa %%xmm1, 0x70(%[ksch])\n\t" /* ksch[7] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x80)
                    AESKEY_EXPAND128
                    "movdqa %%xmm1, 0x80(%[ksch])\n\t" /* ksch[8] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x1b)
                    AESKEY_EXPAND128
                    "movdqa %%xmm1, 0x90(%[ksch])\n\t" /* ksch[9] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x36)
                    AESKEY_EXPAND128
                    "movdqa %%xmm1, 0xa0(%[ksch])\n\t" /* ksch[10] := xmm1  */
                    :
                    : [key] "r" (key), [ksch] "r" (ctx->keyschenc)
                    : "cc", "memory" );
#undef AESKEYGENASSIST_xmm1_xmm2
#undef AESKEY_EXPAND128
    }
  else if (ctx->rounds == 12)
    {
      /* 192-bit key */
#define AESKEYGENASSIST_xmm3_xmm2(imm8) \
	".byte 0x66, 0x0f, 0x3a, 0xdf, 0xd3, " #imm8 " \n\t"
#define AESKEY_EXPAND192 \
	"pshufd $0x55, %%xmm2, %%xmm2\n\t" \
	"movdqu %%xmm1, %%xmm4\n\t" \
	"pslldq $4, %%xmm4\n\t" \
	"pxor %%xmm4, %%xmm1\n\t" \
	"pslldq $4, %%xmm4\n\t" \
	"pxor %%xmm4, %%xmm1\n\t" \
	"pslldq $4, %%xmm4\n\t" \
	"pxor %%xmm4, %%xmm1\n\t" \
	"pxor %%xmm2, %%xmm1\n\t" \
	"pshufd $0xff, %%xmm1, %%xmm2\n\t" \
	"movdqu %%xmm3, %%xmm4\n\t" \
	"pslldq $4, %%xmm4\n\t" \
	"pxor %%xmm4, %%xmm3\n\t" \
	"pxor %%xmm2, %%xmm3\n\t"

      asm volatile ("movdqu (%[key]), %%xmm1\n\t"     /* xmm1 := key[0..15]   */
                    "movq 16(%[key]), %%xmm3\n\t"     /* xmm3 := key[16..23]  */
                    "movdqa %%xmm1, (%[ksch])\n\t"    /* ksch[0] := xmm1  */
                    "movdqa %%xmm3, %%xmm5\n\t"

                    AESKEYGENASSIST_xmm3_xmm2(0x01)
                    AESKEY_EXPAND192
                    "shufpd $0, %%xmm1, %%xmm5\n\t"
                    "movdqa %%xmm5, 0x10(%[ksch])\n\t" /* ksch[1] := xmm5  */
                    "movdqa %%xmm1, %%xmm6\n\t"
                    "shufpd $1, %%xmm3, %%xmm6\n\t"
                    "movdqa %%xmm6, 0x20(%[ksch])\n\t" /* ksch[2] := xmm6  */
                    AESKEYGENASSIST_xmm3_xmm2(0x02)
                    AESKEY_EXPAND192
                    "movdqa %%xmm1, 0x30(%[ksch])\n\t" /* ksch[3] := xmm1  */
                    "movdqa %%xmm3, %%xmm5\n\t"

                    AESKEYGENASSIST_xmm3_xmm2(0x04)
                    AESKEY_EXPAND192
                    "shufpd $0, %%xmm1, %%xmm5\n\t"
                    "movdqa %%xmm5, 0x40(%[ksch])\n\t" /* ksch[4] := xmm5  */
                    "movdqa %%xmm1, %%xmm6\n\t"
                    "shufpd $1, %%xmm3, %%xmm6\n\t"
                    "movdqa %%xmm6, 0x50(%[ksch])\n\t" /* ksch[5] := xmm6  */
                    AESKEYGENASSIST_xmm3_xmm2(0x08)
                    AESKEY_EXPAND192
                    "movdqa %%xmm1, 0x60(%[ksch])\n\t" /* ksch[6] := xmm1  */
                    "movdqa %%xmm3, %%xmm5\n\t"

                    AESKEYGENASSIST_xmm3_xmm2(0x10)
                    AESKEY_EXPAND192
                    "shufpd $0, %%xmm1, %%xmm5\n\t"
                    "movdqa %%xmm5, 0x70(%[ksch])\n\t" /* ksch[7] := xmm5  */
                    "movdqa %%xmm1, %%xmm6\n\t"
                    "shufpd $1, %%xmm3, %%xmm6\n\t"
                    "movdqa %%xmm6, 0x80(%[ksch])\n\t" /* ksch[8] := xmm6  */
                    AESKEYGENASSIST_xmm3_xmm2(0x20)
                    AESKEY_EXPAND192
                    "movdqa %%xmm1, 0x90(%[ksch])\n\t" /* ksch[9] := xmm1  */
                    "movdqa %%xmm3, %%xmm5\n\t"

                    AESKEYGENASSIST_xmm3_xmm2(0x40)
                    AESKEY_EXPAND192
                    "shufpd $0, %%xmm1, %%xmm5\n\t"
                    "movdqa %%xmm5, 0xa0(%[ksch])\n\t" /* ksch[10] := xmm5  */
                    "movdqa %%xmm1, %%xmm6\n\t"
                    "shufpd $1, %%xmm3, %%xmm6\n\t"
                    "movdqa %%xmm6, 0xb0(%[ksch])\n\t" /* ksch[11] := xmm6  */
                    AESKEYGENASSIST_xmm3_xmm2(0x80)
                    AESKEY_EXPAND192
                    "movdqa %%xmm1, 0xc0(%[ksch])\n\t" /* ksch[12] := xmm1  */
                    :
                    : [key] "r" (key), [ksch] "r" (ctx->keyschenc)
                    : "cc", "memory" );
#undef AESKEYGENASSIST_xmm3_xmm2
#undef AESKEY_EXPAND192
    }
  else if (ctx->rounds > 12)
    {
      /* 256-bit key */
#define AESKEYGENASSIST_xmm1_xmm2(imm8) \
	".byte 0x66, 0x0f, 0x3a, 0xdf, 0xd1, " #imm8 " \n\t"
#define AESKEYGENASSIST_xmm3_xmm2(imm8) \
	".byte 0x66, 0x0f, 0x3a, 0xdf, 0xd3, " #imm8 " \n\t"
#define AESKEY_EXPAND256_A \
	"pshufd $0xff, %%xmm2, %%xmm2\n\t" \
	"movdqa %%xmm1, %%xmm4\n\t" \
	"pslldq $4, %%xmm4\n\t" \
	"pxor %%xmm4, %%xmm1\n\t" \
	"pslldq $4, %%xmm4\n\t" \
	"pxor %%xmm4, %%xmm1\n\t" \
	"pslldq $4, %%xmm4\n\t" \
	"pxor %%xmm4, %%xmm1\n\t" \
	"pxor %%xmm2, %%xmm1\n\t"
#define AESKEY_EXPAND256_B \
	"pshufd $0xaa, %%xmm2, %%xmm2\n\t" \
	"movdqa %%xmm3, %%xmm4\n\t" \
	"pslldq $4, %%xmm4\n\t" \
	"pxor %%xmm4, %%xmm3\n\t" \
	"pslldq $4, %%xmm4\n\t" \
	"pxor %%xmm4, %%xmm3\n\t" \
	"pslldq $4, %%xmm4\n\t" \
	"pxor %%xmm4, %%xmm3\n\t" \
	"pxor %%xmm2, %%xmm3\n\t"

      asm volatile ("movdqu (%[key]), %%xmm1\n\t"     /* xmm1 := key[0..15]   */
                    "movdqu 16(%[key]), %%xmm3\n\t"   /* xmm3 := key[16..31]  */
                    "movdqa %%xmm1, (%[ksch])\n\t"     /* ksch[0] := xmm1  */
                    "movdqa %%xmm3, 0x10(%[ksch])\n\t" /* ksch[1] := xmm3  */

                    AESKEYGENASSIST_xmm3_xmm2(0x01)
                    AESKEY_EXPAND256_A
                    "movdqa %%xmm1, 0x20(%[ksch])\n\t" /* ksch[2] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x00)
                    AESKEY_EXPAND256_B
                    "movdqa %%xmm3, 0x30(%[ksch])\n\t" /* ksch[3] := xmm3  */

                    AESKEYGENASSIST_xmm3_xmm2(0x02)
                    AESKEY_EXPAND256_A
                    "movdqa %%xmm1, 0x40(%[ksch])\n\t" /* ksch[4] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x00)
                    AESKEY_EXPAND256_B
                    "movdqa %%xmm3, 0x50(%[ksch])\n\t" /* ksch[5] := xmm3  */

                    AESKEYGENASSIST_xmm3_xmm2(0x04)
                    AESKEY_EXPAND256_A
                    "movdqa %%xmm1, 0x60(%[ksch])\n\t" /* ksch[6] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x00)
                    AESKEY_EXPAND256_B
                    "movdqa %%xmm3, 0x70(%[ksch])\n\t" /* ksch[7] := xmm3  */

                    AESKEYGENASSIST_xmm3_xmm2(0x08)
                    AESKEY_EXPAND256_A
                    "movdqa %%xmm1, 0x80(%[ksch])\n\t" /* ksch[8] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x00)
                    AESKEY_EXPAND256_B
                    "movdqa %%xmm3, 0x90(%[ksch])\n\t" /* ksch[9] := xmm3  */

                    AESKEYGENASSIST_xmm3_xmm2(0x10)
                    AESKEY_EXPAND256_A
                    "movdqa %%xmm1, 0xa0(%[ksch])\n\t" /* ksch[10] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x00)
                    AESKEY_EXPAND256_B
                    "movdqa %%xmm3, 0xb0(%[ksch])\n\t" /* ksch[11] := xmm3  */

                    AESKEYGENASSIST_xmm3_xmm2(0x20)
                    AESKEY_EXPAND256_A
                    "movdqa %%xmm1, 0xc0(%[ksch])\n\t" /* ksch[12] := xmm1  */
                    AESKEYGENASSIST_xmm1_xmm2(0x00)
                    AESKEY_EXPAND256_B
                    "movdqa %%xmm3, 0xd0(%[ksch])\n\t" /* ksch[13] := xmm3  */

                    AESKEYGENASSIST_xmm3_xmm2(0x40)
                    AESKEY_EXPAND256_A
                    "movdqa %%xmm1, 0xe0(%[ksch])\n\t" /* ksch[14] := xmm1  */

                    :
                    : [key] "r" (key), [ksch] "r" (ctx->keyschenc)
                    : "cc", "memory" );
#undef AESKEYGENASSIST_xmm1_xmm2
#undef AESKEYGENASSIST_xmm3_xmm2
#undef AESKEY_EXPAND256_A
#undef AESKEY_EXPAND256_B
    }

  aesni_cleanup();
  aesni_cleanup_2_6();
}


/* Make a decryption key from an encryption key. */
void
_gcry_aes_aesni_prepare_decryption (RIJNDAEL_context *ctx)
{
  /* The AES-NI decrypt instructions use the Equivalent Inverse
     Cipher, thus we can't use the the standard decrypt key
     preparation.  */
  u128_t *ekey = (u128_t *)ctx->keyschenc;
  u128_t *dkey = (u128_t *)ctx->keyschdec;
  int rr;
  int r;

  aesni_prepare();

#define DO_AESNI_AESIMC() \
  asm volatile ("movdqa %[ekey], %%xmm1\n\t" \
                /*"aesimc %%xmm1, %%xmm1\n\t"*/ \
                ".byte 0x66, 0x0f, 0x38, 0xdb, 0xc9\n\t" \
                "movdqa %%xmm1, %[dkey]" \
                : [dkey] "=m" (dkey[r]) \
                : [ekey] "m" (ekey[rr]) \
                : "memory")

  dkey[0] = ekey[ctx->rounds];
  r=1;
  rr=ctx->rounds-1;
  DO_AESNI_AESIMC(); r++; rr--; /* round 1 */
  DO_AESNI_AESIMC(); r++; rr--; /* round 2 */
  DO_AESNI_AESIMC(); r++; rr--; /* round 3 */
  DO_AESNI_AESIMC(); r++; rr--; /* round 4 */
  DO_AESNI_AESIMC(); r++; rr--; /* round 5 */
  DO_AESNI_AESIMC(); r++; rr--; /* round 6 */
  DO_AESNI_AESIMC(); r++; rr--; /* round 7 */
  DO_AESNI_AESIMC(); r++; rr--; /* round 8 */
  DO_AESNI_AESIMC(); r++; rr--; /* round 9 */
  if (ctx->rounds > 10)
    {
      DO_AESNI_AESIMC(); r++; rr--; /* round 10 */
      DO_AESNI_AESIMC(); r++; rr--; /* round 11 */
      if (ctx->rounds > 12)
        {
          DO_AESNI_AESIMC(); r++; rr--; /* round 12 */
          DO_AESNI_AESIMC(); r++; rr--; /* round 13 */
        }
    }

  dkey[r] = ekey[0];

#undef DO_AESNI_AESIMC

  aesni_cleanup();
}


/* Encrypt one block using the Intel AES-NI instructions.  Block is input
 * and output through SSE register xmm0. */
static inline void
do_aesni_enc (const RIJNDAEL_context *ctx)
{
#define aesenc_xmm1_xmm0      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xc1\n\t"
#define aesenclast_xmm1_xmm0  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xc1\n\t"
  asm volatile ("movdqa (%[key]), %%xmm1\n\t"    /* xmm1 := key[0] */
                "pxor   %%xmm1, %%xmm0\n\t"     /* xmm0 ^= key[0] */
                "movdqa 0x10(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x20(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x30(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x40(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x50(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x60(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x70(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x80(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x90(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0xa0(%[key]), %%xmm1\n\t"
                "cmpl $10, %[rounds]\n\t"
                "jz .Lenclast%=\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0xb0(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0xc0(%[key]), %%xmm1\n\t"
                "cmpl $12, %[rounds]\n\t"
                "jz .Lenclast%=\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0xd0(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0xe0(%[key]), %%xmm1\n"

                ".Lenclast%=:\n\t"
                aesenclast_xmm1_xmm0
                "\n"
                :
                : [key] "r" (ctx->keyschenc),
                  [rounds] "r" (ctx->rounds)
                : "cc", "memory");
#undef aesenc_xmm1_xmm0
#undef aesenclast_xmm1_xmm0
}


/* Decrypt one block using the Intel AES-NI instructions.  Block is input
 * and output through SSE register xmm0. */
static inline void
do_aesni_dec (const RIJNDAEL_context *ctx)
{
#define aesdec_xmm1_xmm0      ".byte 0x66, 0x0f, 0x38, 0xde, 0xc1\n\t"
#define aesdeclast_xmm1_xmm0  ".byte 0x66, 0x0f, 0x38, 0xdf, 0xc1\n\t"
  asm volatile ("movdqa (%[key]), %%xmm1\n\t"
                "pxor   %%xmm1, %%xmm0\n\t"     /* xmm0 ^= key[0] */
                "movdqa 0x10(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0x20(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0x30(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0x40(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0x50(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0x60(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0x70(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0x80(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0x90(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0xa0(%[key]), %%xmm1\n\t"
                "cmpl $10, %[rounds]\n\t"
                "jz .Ldeclast%=\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0xb0(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0xc0(%[key]), %%xmm1\n\t"
                "cmpl $12, %[rounds]\n\t"
                "jz .Ldeclast%=\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0xd0(%[key]), %%xmm1\n\t"
                aesdec_xmm1_xmm0
                "movdqa 0xe0(%[key]), %%xmm1\n"

                ".Ldeclast%=:\n\t"
                aesdeclast_xmm1_xmm0
                "\n"
                :
                : [key] "r" (ctx->keyschdec),
                  [rounds] "r" (ctx->rounds)
                : "cc", "memory");
#undef aesdec_xmm1_xmm0
#undef aesdeclast_xmm1_xmm0
}


/* Encrypt four blocks using the Intel AES-NI instructions.  Blocks are input
 * and output through SSE registers xmm1 to xmm4.  */
static inline void
do_aesni_enc_vec4 (const RIJNDAEL_context *ctx)
{
#define aesenc_xmm0_xmm1      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xc8\n\t"
#define aesenc_xmm0_xmm2      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xd0\n\t"
#define aesenc_xmm0_xmm3      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xd8\n\t"
#define aesenc_xmm0_xmm4      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xe0\n\t"
#define aesenclast_xmm0_xmm1  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xc8\n\t"
#define aesenclast_xmm0_xmm2  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xd0\n\t"
#define aesenclast_xmm0_xmm3  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xd8\n\t"
#define aesenclast_xmm0_xmm4  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xe0\n\t"
  asm volatile ("movdqa (%[key]), %%xmm0\n\t"
                "pxor   %%xmm0, %%xmm1\n\t"     /* xmm1 ^= key[0] */
                "pxor   %%xmm0, %%xmm2\n\t"     /* xmm2 ^= key[0] */
                "pxor   %%xmm0, %%xmm3\n\t"     /* xmm3 ^= key[0] */
                "pxor   %%xmm0, %%xmm4\n\t"     /* xmm4 ^= key[0] */
                "movdqa 0x10(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0x20(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0x30(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0x40(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0x50(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0x60(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0x70(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0x80(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0x90(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0xa0(%[key]), %%xmm0\n\t"
                "cmpl $10, %[rounds]\n\t"
                "jz .Ldeclast%=\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0xb0(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0xc0(%[key]), %%xmm0\n\t"
                "cmpl $12, %[rounds]\n\t"
                "jz .Ldeclast%=\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0xd0(%[key]), %%xmm0\n\t"
                aesenc_xmm0_xmm1
                aesenc_xmm0_xmm2
                aesenc_xmm0_xmm3
                aesenc_xmm0_xmm4
                "movdqa 0xe0(%[key]), %%xmm0\n"

                ".Ldeclast%=:\n\t"
                aesenclast_xmm0_xmm1
                aesenclast_xmm0_xmm2
                aesenclast_xmm0_xmm3
                aesenclast_xmm0_xmm4
                : /* no output */
                : [key] "r" (ctx->keyschenc),
                  [rounds] "r" (ctx->rounds)
                : "cc", "memory");
#undef aesenc_xmm0_xmm1
#undef aesenc_xmm0_xmm2
#undef aesenc_xmm0_xmm3
#undef aesenc_xmm0_xmm4
#undef aesenclast_xmm0_xmm1
#undef aesenclast_xmm0_xmm2
#undef aesenclast_xmm0_xmm3
#undef aesenclast_xmm0_xmm4
}


/* Decrypt four blocks using the Intel AES-NI instructions.  Blocks are input
 * and output through SSE registers xmm1 to xmm4.  */
static inline void
do_aesni_dec_vec4 (const RIJNDAEL_context *ctx)
{
#define aesdec_xmm0_xmm1 ".byte 0x66, 0x0f, 0x38, 0xde, 0xc8\n\t"
#define aesdec_xmm0_xmm2 ".byte 0x66, 0x0f, 0x38, 0xde, 0xd0\n\t"
#define aesdec_xmm0_xmm3 ".byte 0x66, 0x0f, 0x38, 0xde, 0xd8\n\t"
#define aesdec_xmm0_xmm4 ".byte 0x66, 0x0f, 0x38, 0xde, 0xe0\n\t"
#define aesdeclast_xmm0_xmm1 ".byte 0x66, 0x0f, 0x38, 0xdf, 0xc8\n\t"
#define aesdeclast_xmm0_xmm2 ".byte 0x66, 0x0f, 0x38, 0xdf, 0xd0\n\t"
#define aesdeclast_xmm0_xmm3 ".byte 0x66, 0x0f, 0x38, 0xdf, 0xd8\n\t"
#define aesdeclast_xmm0_xmm4 ".byte 0x66, 0x0f, 0x38, 0xdf, 0xe0\n\t"
  asm volatile ("movdqa (%[key]), %%xmm0\n\t"
                "pxor   %%xmm0, %%xmm1\n\t"     /* xmm1 ^= key[0] */
                "pxor   %%xmm0, %%xmm2\n\t"     /* xmm2 ^= key[0] */
                "pxor   %%xmm0, %%xmm3\n\t"     /* xmm3 ^= key[0] */
                "pxor   %%xmm0, %%xmm4\n\t"     /* xmm4 ^= key[0] */
                "movdqa 0x10(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0x20(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0x30(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0x40(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0x50(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0x60(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0x70(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0x80(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0x90(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0xa0(%[key]), %%xmm0\n\t"
                "cmpl $10, %[rounds]\n\t"
                "jz .Ldeclast%=\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0xb0(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0xc0(%[key]), %%xmm0\n\t"
                "cmpl $12, %[rounds]\n\t"
                "jz .Ldeclast%=\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0xd0(%[key]), %%xmm0\n\t"
                aesdec_xmm0_xmm1
                aesdec_xmm0_xmm2
                aesdec_xmm0_xmm3
                aesdec_xmm0_xmm4
                "movdqa 0xe0(%[key]), %%xmm0\n"

                ".Ldeclast%=:\n\t"
                aesdeclast_xmm0_xmm1
                aesdeclast_xmm0_xmm2
                aesdeclast_xmm0_xmm3
                aesdeclast_xmm0_xmm4
                : /* no output */
                : [key] "r" (ctx->keyschdec),
                  [rounds] "r" (ctx->rounds)
                : "cc", "memory");
#undef aesdec_xmm0_xmm1
#undef aesdec_xmm0_xmm2
#undef aesdec_xmm0_xmm3
#undef aesdec_xmm0_xmm4
#undef aesdeclast_xmm0_xmm1
#undef aesdeclast_xmm0_xmm2
#undef aesdeclast_xmm0_xmm3
#undef aesdeclast_xmm0_xmm4
}


#ifdef __x86_64__

/* Encrypt eight blocks using the Intel AES-NI instructions.  Blocks are input
 * and output through SSE registers xmm1 to xmm4 and xmm8 to xmm11.  */
static inline void
do_aesni_enc_vec8 (const RIJNDAEL_context *ctx)
{
  asm volatile ("movdqa (%[key]), %%xmm0\n\t"
                "pxor   %%xmm0, %%xmm1\n\t"     /* xmm1 ^= key[0] */
                "pxor   %%xmm0, %%xmm2\n\t"     /* xmm2 ^= key[0] */
                "pxor   %%xmm0, %%xmm3\n\t"     /* xmm3 ^= key[0] */
                "pxor   %%xmm0, %%xmm4\n\t"     /* xmm4 ^= key[0] */
                "pxor   %%xmm0, %%xmm8\n\t"     /* xmm8 ^= key[0] */
                "pxor   %%xmm0, %%xmm9\n\t"     /* xmm9 ^= key[0] */
                "pxor   %%xmm0, %%xmm10\n\t"     /* xmm10 ^= key[0] */
                "pxor   %%xmm0, %%xmm11\n\t"     /* xmm11 ^= key[0] */
                "movdqa 0x10(%[key]), %%xmm0\n\t"
                "cmpl $12, %[rounds]\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0x20(%[key]), %%xmm0\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0x30(%[key]), %%xmm0\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0x40(%[key]), %%xmm0\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0x50(%[key]), %%xmm0\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0x60(%[key]), %%xmm0\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0x70(%[key]), %%xmm0\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0x80(%[key]), %%xmm0\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0x90(%[key]), %%xmm0\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0xa0(%[key]), %%xmm0\n\t"
                "jb .Ldeclast%=\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0xb0(%[key]), %%xmm0\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0xc0(%[key]), %%xmm0\n\t"
                "je .Ldeclast%=\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0xd0(%[key]), %%xmm0\n\t"
                "aesenc %%xmm0, %%xmm1\n\t"
                "aesenc %%xmm0, %%xmm2\n\t"
                "aesenc %%xmm0, %%xmm3\n\t"
                "aesenc %%xmm0, %%xmm4\n\t"
                "aesenc %%xmm0, %%xmm8\n\t"
                "aesenc %%xmm0, %%xmm9\n\t"
                "aesenc %%xmm0, %%xmm10\n\t"
                "aesenc %%xmm0, %%xmm11\n\t"
                "movdqa 0xe0(%[key]), %%xmm0\n"

                ".Ldeclast%=:\n\t"
                "aesenclast %%xmm0, %%xmm1\n\t"
                "aesenclast %%xmm0, %%xmm2\n\t"
                "aesenclast %%xmm0, %%xmm3\n\t"
                "aesenclast %%xmm0, %%xmm4\n\t"
                "aesenclast %%xmm0, %%xmm8\n\t"
                "aesenclast %%xmm0, %%xmm9\n\t"
                "aesenclast %%xmm0, %%xmm10\n\t"
                "aesenclast %%xmm0, %%xmm11\n\t"
                : /* no output */
                : [key] "r" (ctx->keyschenc),
                  [rounds] "r" (ctx->rounds)
                : "cc", "memory");
}


/* Decrypt eight blocks using the Intel AES-NI instructions.  Blocks are input
 * and output through SSE registers xmm1 to xmm4 and xmm8 to xmm11.  */
static inline void
do_aesni_dec_vec8 (const RIJNDAEL_context *ctx)
{
  asm volatile ("movdqa (%[key]), %%xmm0\n\t"
                "pxor   %%xmm0, %%xmm1\n\t"     /* xmm1 ^= key[0] */
                "pxor   %%xmm0, %%xmm2\n\t"     /* xmm2 ^= key[0] */
                "pxor   %%xmm0, %%xmm3\n\t"     /* xmm3 ^= key[0] */
                "pxor   %%xmm0, %%xmm4\n\t"     /* xmm4 ^= key[0] */
                "pxor   %%xmm0, %%xmm8\n\t"     /* xmm8 ^= key[0] */
                "pxor   %%xmm0, %%xmm9\n\t"     /* xmm9 ^= key[0] */
                "pxor   %%xmm0, %%xmm10\n\t"    /* xmm10 ^= key[0] */
                "pxor   %%xmm0, %%xmm11\n\t"    /* xmm11 ^= key[0] */
                "movdqa 0x10(%[key]), %%xmm0\n\t"
                "cmpl $12, %[rounds]\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0x20(%[key]), %%xmm0\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0x30(%[key]), %%xmm0\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0x40(%[key]), %%xmm0\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0x50(%[key]), %%xmm0\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0x60(%[key]), %%xmm0\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0x70(%[key]), %%xmm0\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0x80(%[key]), %%xmm0\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0x90(%[key]), %%xmm0\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0xa0(%[key]), %%xmm0\n\t"
                "jb .Ldeclast%=\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0xb0(%[key]), %%xmm0\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0xc0(%[key]), %%xmm0\n\t"
                "je .Ldeclast%=\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0xd0(%[key]), %%xmm0\n\t"
                "aesdec %%xmm0, %%xmm1\n\t"
                "aesdec %%xmm0, %%xmm2\n\t"
                "aesdec %%xmm0, %%xmm3\n\t"
                "aesdec %%xmm0, %%xmm4\n\t"
                "aesdec %%xmm0, %%xmm8\n\t"
                "aesdec %%xmm0, %%xmm9\n\t"
                "aesdec %%xmm0, %%xmm10\n\t"
                "aesdec %%xmm0, %%xmm11\n\t"
                "movdqa 0xe0(%[key]), %%xmm0\n"

                ".Ldeclast%=:\n\t"
                "aesdeclast %%xmm0, %%xmm1\n\t"
                "aesdeclast %%xmm0, %%xmm2\n\t"
                "aesdeclast %%xmm0, %%xmm3\n\t"
                "aesdeclast %%xmm0, %%xmm4\n\t"
                "aesdeclast %%xmm0, %%xmm8\n\t"
                "aesdeclast %%xmm0, %%xmm9\n\t"
                "aesdeclast %%xmm0, %%xmm10\n\t"
                "aesdeclast %%xmm0, %%xmm11\n\t"
                : /* no output */
                : [key] "r" (ctx->keyschdec),
                  [rounds] "r" (ctx->rounds)
                : "cc", "memory");
}

#endif /* __x86_64__ */


/* Perform a CTR encryption round using the counter CTR and the input
   block A.  Write the result to the output block B and update CTR.
   CTR needs to be a 16 byte aligned little-endian value.  */
static void
do_aesni_ctr (const RIJNDAEL_context *ctx,
              unsigned char *ctr, unsigned char *b, const unsigned char *a)
{
#define aesenc_xmm1_xmm0      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xc1\n\t"
#define aesenclast_xmm1_xmm0  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xc1\n\t"

  asm volatile ("movdqa %%xmm5, %%xmm0\n\t"     /* xmm0 := CTR (xmm5)  */
                "pcmpeqd %%xmm1, %%xmm1\n\t"
                "psrldq $8, %%xmm1\n\t"         /* xmm1 = -1 */

                "pshufb %%xmm6, %%xmm5\n\t"
                "psubq  %%xmm1, %%xmm5\n\t"     /* xmm5++ (big endian) */

                /* detect if 64-bit carry handling is needed */
                "cmpl   $0xffffffff, 8(%[ctr])\n\t"
                "jne    .Lno_carry%=\n\t"
                "cmpl   $0xffffffff, 12(%[ctr])\n\t"
                "jne    .Lno_carry%=\n\t"

                "pslldq $8, %%xmm1\n\t"         /* move lower 64-bit to high */
                "psubq   %%xmm1, %%xmm5\n\t"    /* add carry to upper 64bits */

                ".Lno_carry%=:\n\t"

                "pshufb %%xmm6, %%xmm5\n\t"
                "movdqa %%xmm5, (%[ctr])\n\t"   /* Update CTR (mem).       */

                "pxor (%[key]), %%xmm0\n\t"     /* xmm1 ^= key[0]    */
                "movdqa 0x10(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x20(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x30(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x40(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x50(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x60(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x70(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x80(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0x90(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0xa0(%[key]), %%xmm1\n\t"
                "cmpl $10, %[rounds]\n\t"
                "jz .Lenclast%=\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0xb0(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0xc0(%[key]), %%xmm1\n\t"
                "cmpl $12, %[rounds]\n\t"
                "jz .Lenclast%=\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0xd0(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                "movdqa 0xe0(%[key]), %%xmm1\n"

                ".Lenclast%=:\n\t"
                aesenclast_xmm1_xmm0
                "movdqu %[src], %%xmm1\n\t"      /* xmm1 := input   */
                "pxor %%xmm1, %%xmm0\n\t"        /* EncCTR ^= input  */
                "movdqu %%xmm0, %[dst]"          /* Store EncCTR.    */

                : [dst] "=m" (*b)
                : [src] "m" (*a),
                  [ctr] "r" (ctr),
                  [key] "r" (ctx->keyschenc),
                  [rounds] "g" (ctx->rounds)
                : "cc", "memory");
#undef aesenc_xmm1_xmm0
#undef aesenclast_xmm1_xmm0
}


/* Four blocks at a time variant of do_aesni_ctr.  */
static void
do_aesni_ctr_4 (const RIJNDAEL_context *ctx,
                unsigned char *ctr, unsigned char *b, const unsigned char *a)
{
  static const byte bige_addb_const[4][16] __attribute__ ((aligned (16))) =
    {
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 },
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 },
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4 }
    };
  const void *bige_addb = bige_addb_const;
#define aesenc_xmm1_xmm0      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xc1\n\t"
#define aesenc_xmm1_xmm2      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xd1\n\t"
#define aesenc_xmm1_xmm3      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xd9\n\t"
#define aesenc_xmm1_xmm4      ".byte 0x66, 0x0f, 0x38, 0xdc, 0xe1\n\t"
#define aesenclast_xmm1_xmm0  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xc1\n\t"
#define aesenclast_xmm1_xmm2  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xd1\n\t"
#define aesenclast_xmm1_xmm3  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xd9\n\t"
#define aesenclast_xmm1_xmm4  ".byte 0x66, 0x0f, 0x38, 0xdd, 0xe1\n\t"

  /* Register usage:
      [key] keyschedule
      xmm0  CTR-0
      xmm1  temp / round key
      xmm2  CTR-1
      xmm3  CTR-2
      xmm4  CTR-3
      xmm5  copy of *ctr
      xmm6  endian swapping mask
   */

  asm volatile (/* detect if 8-bit carry handling is needed */
                "cmpb   $0xfb, 15(%[ctr])\n\t"
                "ja     .Ladd32bit%=\n\t"

                "movdqa %%xmm5, %%xmm0\n\t"     /* xmm0 := CTR (xmm5) */
                "movdqa 0*16(%[addb]), %%xmm2\n\t"  /* xmm2 := be(1) */
                "movdqa 1*16(%[addb]), %%xmm3\n\t"  /* xmm3 := be(2) */
                "movdqa 2*16(%[addb]), %%xmm4\n\t"  /* xmm4 := be(3) */
                "movdqa 3*16(%[addb]), %%xmm5\n\t"  /* xmm5 := be(4) */
                "paddb  %%xmm0, %%xmm2\n\t"     /* xmm2 := be(1) + CTR (xmm0) */
                "paddb  %%xmm0, %%xmm3\n\t"     /* xmm3 := be(2) + CTR (xmm0) */
                "paddb  %%xmm0, %%xmm4\n\t"     /* xmm4 := be(3) + CTR (xmm0) */
                "paddb  %%xmm0, %%xmm5\n\t"     /* xmm5 := be(4) + CTR (xmm0) */
                "movdqa (%[key]), %%xmm1\n\t"   /* xmm1 := key[0] */
                "jmp    .Lstore_ctr%=\n\t"

                ".Ladd32bit%=:\n\t"
                "movdqa %%xmm5, %%xmm0\n\t"     /* xmm0, xmm2 := CTR (xmm5) */
                "movdqa %%xmm0, %%xmm2\n\t"
                "pcmpeqd %%xmm1, %%xmm1\n\t"
                "psrldq $8, %%xmm1\n\t"         /* xmm1 = -1 */

                "pshufb %%xmm6, %%xmm2\n\t"     /* xmm2 := le(xmm2) */
                "psubq  %%xmm1, %%xmm2\n\t"     /* xmm2++           */
                "movdqa %%xmm2, %%xmm3\n\t"     /* xmm3 := xmm2     */
                "psubq  %%xmm1, %%xmm3\n\t"     /* xmm3++           */
                "movdqa %%xmm3, %%xmm4\n\t"     /* xmm4 := xmm3     */
                "psubq  %%xmm1, %%xmm4\n\t"     /* xmm4++           */
                "movdqa %%xmm4, %%xmm5\n\t"     /* xmm5 := xmm4     */
                "psubq  %%xmm1, %%xmm5\n\t"     /* xmm5++           */

                /* detect if 64-bit carry handling is needed */
                "cmpl   $0xffffffff, 8(%[ctr])\n\t"
                "jne    .Lno_carry%=\n\t"
                "movl   12(%[ctr]), %%esi\n\t"
                "bswapl %%esi\n\t"
                "cmpl   $0xfffffffc, %%esi\n\t"
                "jb     .Lno_carry%=\n\t"       /* no carry */

                "pslldq $8, %%xmm1\n\t"         /* move lower 64-bit to high */
                "je     .Lcarry_xmm5%=\n\t"     /* esi == 0xfffffffc */
                "cmpl   $0xfffffffe, %%esi\n\t"
                "jb     .Lcarry_xmm4%=\n\t"     /* esi == 0xfffffffd */
                "je     .Lcarry_xmm3%=\n\t"     /* esi == 0xfffffffe */
                /* esi == 0xffffffff */

                "psubq   %%xmm1, %%xmm2\n\t"
                ".Lcarry_xmm3%=:\n\t"
                "psubq   %%xmm1, %%xmm3\n\t"
                ".Lcarry_xmm4%=:\n\t"
                "psubq   %%xmm1, %%xmm4\n\t"
                ".Lcarry_xmm5%=:\n\t"
                "psubq   %%xmm1, %%xmm5\n\t"

                ".Lno_carry%=:\n\t"
                "movdqa (%[key]), %%xmm1\n\t"   /* xmm1 := key[0]    */

                "pshufb %%xmm6, %%xmm2\n\t"     /* xmm2 := be(xmm2) */
                "pshufb %%xmm6, %%xmm3\n\t"     /* xmm3 := be(xmm3) */
                "pshufb %%xmm6, %%xmm4\n\t"     /* xmm4 := be(xmm4) */
                "pshufb %%xmm6, %%xmm5\n\t"     /* xmm5 := be(xmm5) */

                ".Lstore_ctr%=:\n\t"
                "movdqa %%xmm5, (%[ctr])\n\t"   /* Update CTR (mem).  */
                :
                : [ctr] "r" (ctr),
                  [key] "r" (ctx->keyschenc),
                  [addb] "r" (bige_addb)
                : "%esi", "cc", "memory");

  asm volatile ("pxor   %%xmm1, %%xmm0\n\t"     /* xmm0 ^= key[0]    */
                "pxor   %%xmm1, %%xmm2\n\t"     /* xmm2 ^= key[0]    */
                "pxor   %%xmm1, %%xmm3\n\t"     /* xmm3 ^= key[0]    */
                "pxor   %%xmm1, %%xmm4\n\t"     /* xmm4 ^= key[0]    */
                "movdqa 0x10(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0x20(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0x30(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0x40(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0x50(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0x60(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0x70(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0x80(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0x90(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0xa0(%[key]), %%xmm1\n\t"
                "cmpl $10, %[rounds]\n\t"
                "jz .Lenclast%=\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0xb0(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0xc0(%[key]), %%xmm1\n\t"
                "cmpl $12, %[rounds]\n\t"
                "jz .Lenclast%=\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0xd0(%[key]), %%xmm1\n\t"
                aesenc_xmm1_xmm0
                aesenc_xmm1_xmm2
                aesenc_xmm1_xmm3
                aesenc_xmm1_xmm4
                "movdqa 0xe0(%[key]), %%xmm1\n"

                ".Lenclast%=:\n\t"
                aesenclast_xmm1_xmm0
                aesenclast_xmm1_xmm2
                aesenclast_xmm1_xmm3
                aesenclast_xmm1_xmm4
                :
                : [key] "r" (ctx->keyschenc),
                  [rounds] "r" (ctx->rounds)
                : "cc", "memory");

  asm volatile ("movdqu (%[src]), %%xmm1\n\t"    /* Get block 1.      */
                "pxor %%xmm1, %%xmm0\n\t"        /* EncCTR-1 ^= input */
                "movdqu %%xmm0, (%[dst])\n\t"    /* Store block 1     */

                "movdqu 16(%[src]), %%xmm1\n\t"  /* Get block 2.      */
                "pxor %%xmm1, %%xmm2\n\t"        /* EncCTR-2 ^= input */
                "movdqu %%xmm2, 16(%[dst])\n\t"  /* Store block 2.    */

                "movdqu 32(%[src]), %%xmm1\n\t"  /* Get block 3.      */
                "pxor %%xmm1, %%xmm3\n\t"        /* EncCTR-3 ^= input */
                "movdqu %%xmm3, 32(%[dst])\n\t"  /* Store block 3.    */

                "movdqu 48(%[src]), %%xmm1\n\t"  /* Get block 4.      */
                "pxor %%xmm1, %%xmm4\n\t"        /* EncCTR-4 ^= input */
                "movdqu %%xmm4, 48(%[dst])"      /* Store block 4.   */
                :
                : [src] "r" (a),
                  [dst] "r" (b)
                : "memory");
#undef aesenc_xmm1_xmm0
#undef aesenc_xmm1_xmm2
#undef aesenc_xmm1_xmm3
#undef aesenc_xmm1_xmm4
#undef aesenclast_xmm1_xmm0
#undef aesenclast_xmm1_xmm2
#undef aesenclast_xmm1_xmm3
#undef aesenclast_xmm1_xmm4
}


#ifdef __x86_64__

/* Eight blocks at a time variant of do_aesni_ctr.  */
static void
do_aesni_ctr_8 (const RIJNDAEL_context *ctx,
                unsigned char *ctr, unsigned char *b, const unsigned char *a)
{
  static const byte bige_addb_const[8][16] __attribute__ ((aligned (16))) =
    {
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 },
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 },
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4 },
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5 },
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6 },
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7 },
      { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8 }
    };
  const void *bige_addb = bige_addb_const;

  /* Register usage:
      [key] keyschedule
      xmm0  CTR-0
      xmm1  temp / round key
      xmm2  CTR-1
      xmm3  CTR-2
      xmm4  CTR-3
      xmm5  copy of *ctr
      xmm6  endian swapping mask
      xmm8  CTR-4
      xmm9  CTR-5
      xmm10 CTR-6
      xmm11 CTR-7
      xmm12 temp
      xmm13 temp
      xmm14 temp
      xmm15 temp
   */

  asm volatile (/* detect if 8-bit carry handling is needed */
                "cmpb   $0xf7, 15(%[ctr])\n\t"
                "ja     .Ladd32bit%=\n\t"

                "movdqa %%xmm5, %%xmm0\n\t"     /* xmm0 := CTR (xmm5) */
                "movdqa 0*16(%[addb]), %%xmm2\n\t"  /* xmm2 := be(1) */
                "movdqa 1*16(%[addb]), %%xmm3\n\t"  /* xmm3 := be(2) */
                "movdqa 2*16(%[addb]), %%xmm4\n\t"  /* xmm4 := be(3) */
                "movdqa 3*16(%[addb]), %%xmm8\n\t"  /* xmm8 := be(4) */
                "movdqa 4*16(%[addb]), %%xmm9\n\t"  /* xmm9 := be(5) */
                "movdqa 5*16(%[addb]), %%xmm10\n\t" /* xmm10 := be(6) */
                "movdqa 6*16(%[addb]), %%xmm11\n\t" /* xmm11 := be(7) */
                "movdqa 7*16(%[addb]), %%xmm5\n\t"  /* xmm5 := be(8) */
                "movdqa (%[key]), %%xmm1\n\t"   /* xmm1 := key[0] */
                "paddb  %%xmm0, %%xmm2\n\t"     /* xmm2 := be(1) + CTR (xmm0) */
                "paddb  %%xmm0, %%xmm3\n\t"     /* xmm3 := be(2) + CTR (xmm0) */
                "paddb  %%xmm0, %%xmm4\n\t"     /* xmm4 := be(3) + CTR (xmm0) */
                "paddb  %%xmm0, %%xmm8\n\t"     /* xmm8 := be(4) + CTR (xmm0) */
                "paddb  %%xmm0, %%xmm9\n\t"     /* xmm9 := be(5) + CTR (xmm0) */
                "paddb  %%xmm0, %%xmm10\n\t"    /* xmm10 := be(6) + CTR (xmm0) */
                "paddb  %%xmm0, %%xmm11\n\t"    /* xmm11 := be(7) + CTR (xmm0) */
                "paddb  %%xmm0, %%xmm5\n\t"     /* xmm5 := be(8) + CTR (xmm0) */
                "jmp    .Lstore_ctr%=\n\t"

                ".Ladd32bit%=:\n\t"
                "movdqa %%xmm5, %%xmm0\n\t"     /* xmm0, xmm2 := CTR (xmm5) */
                "movdqa %%xmm0, %%xmm2\n\t"
                "pcmpeqd %%xmm1, %%xmm1\n\t"
                "psrldq $8, %%xmm1\n\t"         /* xmm1 = -1 */

                "pshufb %%xmm6, %%xmm2\n\t"     /* xmm2 := le(xmm2) */
                "psubq  %%xmm1, %%xmm2\n\t"     /* xmm2++           */
                "movdqa %%xmm2, %%xmm3\n\t"     /* xmm3 := xmm2     */
                "psubq  %%xmm1, %%xmm3\n\t"     /* xmm3++           */
                "movdqa %%xmm3, %%xmm4\n\t"     /* xmm4 := xmm3     */
                "psubq  %%xmm1, %%xmm4\n\t"     /* xmm4++           */
                "movdqa %%xmm4, %%xmm8\n\t"     /* xmm8 := xmm4     */
                "psubq  %%xmm1, %%xmm8\n\t"     /* xmm8++           */
                "movdqa %%xmm8, %%xmm9\n\t"     /* xmm9 := xmm8     */
                "psubq  %%xmm1, %%xmm9\n\t"     /* xmm9++           */
                "movdqa %%xmm9, %%xmm10\n\t"    /* xmm10 := xmm9    */
                "psubq  %%xmm1, %%xmm10\n\t"    /* xmm10++          */
                "movdqa %%xmm10, %%xmm11\n\t"   /* xmm11 := xmm10   */
                "psubq  %%xmm1, %%xmm11\n\t"    /* xmm11++          */
                "movdqa %%xmm11, %%xmm5\n\t"    /* xmm5 := xmm11    */
                "psubq  %%xmm1, %%xmm5\n\t"     /* xmm5++           */

                /* detect if 64-bit carry handling is needed */
                "cmpl   $0xffffffff, 8(%[ctr])\n\t"
                "jne    .Lno_carry%=\n\t"
                "movl   12(%[ctr]), %%esi\n\t"
                "bswapl %%esi\n\t"
                "cmpl   $0xfffffff8, %%esi\n\t"
                "jb     .Lno_carry%=\n\t"       /* no carry */

                "pslldq $8, %%xmm1\n\t"         /* move lower 64-bit to high */
                "je     .Lcarry_xmm5%=\n\t"     /* esi == 0xfffffff8 */
                "cmpl   $0xfffffffa, %%esi\n\t"
                "jb     .Lcarry_xmm11%=\n\t"     /* esi == 0xfffffff9 */
                "je     .Lcarry_xmm10%=\n\t"     /* esi == 0xfffffffa */
                "cmpl   $0xfffffffc, %%esi\n\t"
                "jb     .Lcarry_xmm9%=\n\t"     /* esi == 0xfffffffb */
                "je     .Lcarry_xmm8%=\n\t"     /* esi == 0xfffffffc */
                "cmpl   $0xfffffffe, %%esi\n\t"
                "jb     .Lcarry_xmm4%=\n\t"     /* esi == 0xfffffffd */
                "je     .Lcarry_xmm3%=\n\t"     /* esi == 0xfffffffe */
                /* esi == 0xffffffff */

                "psubq   %%xmm1, %%xmm2\n\t"
                ".Lcarry_xmm3%=:\n\t"
                "psubq   %%xmm1, %%xmm3\n\t"
                ".Lcarry_xmm4%=:\n\t"
                "psubq   %%xmm1, %%xmm4\n\t"
                ".Lcarry_xmm8%=:\n\t"
                "psubq   %%xmm1, %%xmm8\n\t"
                ".Lcarry_xmm9%=:\n\t"
                "psubq   %%xmm1, %%xmm9\n\t"
                ".Lcarry_xmm10%=:\n\t"
                "psubq   %%xmm1, %%xmm10\n\t"
                ".Lcarry_xmm11%=:\n\t"
                "psubq   %%xmm1, %%xmm11\n\t"
                ".Lcarry_xmm5%=:\n\t"
                "psubq   %%xmm1, %%xmm5\n\t"

                ".Lno_carry%=:\n\t"
                "movdqa (%[key]), %%xmm1\n\t"   /* xmm1 := key[0]    */

                "pshufb %%xmm6, %%xmm2\n\t"     /* xmm2 := be(xmm2) */
                "pshufb %%xmm6, %%xmm3\n\t"     /* xmm3 := be(xmm3) */
                "pshufb %%xmm6, %%xmm4\n\t"     /* xmm4 := be(xmm4) */
                "pshufb %%xmm6, %%xmm5\n\t"     /* xmm5 := be(xmm5) */
                "pshufb %%xmm6, %%xmm8\n\t"     /* xmm8 := be(xmm8) */
                "pshufb %%xmm6, %%xmm9\n\t"     /* xmm9 := be(xmm9) */
                "pshufb %%xmm6, %%xmm10\n\t"    /* xmm10 := be(xmm10) */
                "pshufb %%xmm6, %%xmm11\n\t"    /* xmm11 := be(xmm11) */

                ".Lstore_ctr%=:\n\t"
                "movdqa %%xmm5, (%[ctr])\n\t"   /* Update CTR (mem).  */
                :
                : [ctr] "r" (ctr),
                  [key] "r" (ctx->keyschenc),
                  [addb] "r" (bige_addb)
                : "%esi", "cc", "memory");

  asm volatile ("pxor   %%xmm1, %%xmm0\n\t"     /* xmm0 ^= key[0]    */
                "pxor   %%xmm1, %%xmm2\n\t"     /* xmm2 ^= key[0]    */
                "pxor   %%xmm1, %%xmm3\n\t"     /* xmm3 ^= key[0]    */
                "pxor   %%xmm1, %%xmm4\n\t"     /* xmm4 ^= key[0]    */
                "pxor   %%xmm1, %%xmm8\n\t"     /* xmm8 ^= key[0]    */
                "pxor   %%xmm1, %%xmm9\n\t"     /* xmm9 ^= key[0]    */
                "pxor   %%xmm1, %%xmm10\n\t"    /* xmm10 ^= key[0]   */
                "pxor   %%xmm1, %%xmm11\n\t"    /* xmm11 ^= key[0]   */
                "movdqa 0x10(%[key]), %%xmm1\n\t"
                "cmpl $12, %[rounds]\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0x20(%[key]), %%xmm1\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0x30(%[key]), %%xmm1\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0x40(%[key]), %%xmm1\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0x50(%[key]), %%xmm1\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0x60(%[key]), %%xmm1\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0x70(%[key]), %%xmm1\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0x80(%[key]), %%xmm1\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0x90(%[key]), %%xmm1\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0xa0(%[key]), %%xmm1\n\t"
                "jb .Lenclast%=\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0xb0(%[key]), %%xmm1\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0xc0(%[key]), %%xmm1\n\t"
                "je .Lenclast%=\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0xd0(%[key]), %%xmm1\n\t"
                "aesenc %%xmm1, %%xmm0\n\t"
                "aesenc %%xmm1, %%xmm2\n\t"
                "aesenc %%xmm1, %%xmm3\n\t"
                "aesenc %%xmm1, %%xmm4\n\t"
                "aesenc %%xmm1, %%xmm8\n\t"
                "aesenc %%xmm1, %%xmm9\n\t"
                "aesenc %%xmm1, %%xmm10\n\t"
                "aesenc %%xmm1, %%xmm11\n\t"
                "movdqa 0xe0(%[key]), %%xmm1\n"

                ".Lenclast%=:\n\t"
                "aesenclast %%xmm1, %%xmm0\n\t"
                "aesenclast %%xmm1, %%xmm2\n\t"
                "aesenclast %%xmm1, %%xmm3\n\t"
                "aesenclast %%xmm1, %%xmm4\n\t"
                "aesenclast %%xmm1, %%xmm8\n\t"
                "aesenclast %%xmm1, %%xmm9\n\t"
                "aesenclast %%xmm1, %%xmm10\n\t"
                "aesenclast %%xmm1, %%xmm11\n\t"
                :
                : [key] "r" (ctx->keyschenc),
                  [rounds] "r" (ctx->rounds)
                : "cc", "memory");

  asm volatile ("movdqu 0*16(%[src]), %%xmm12\n\t" /* Get block 1.      */
                "movdqu 1*16(%[src]), %%xmm13\n\t" /* Get block 2.      */
                "movdqu 2*16(%[src]), %%xmm14\n\t" /* Get block 3.      */
                "movdqu 3*16(%[src]), %%xmm15\n\t" /* Get block 4.      */
                "movdqu 4*16(%[src]), %%xmm1\n\t"  /* Get block 5.      */
                "pxor %%xmm12, %%xmm0\n\t"         /* EncCTR-1 ^= input */
                "movdqu 5*16(%[src]), %%xmm12\n\t" /* Get block 6.      */
                "pxor %%xmm13, %%xmm2\n\t"         /* EncCTR-2 ^= input */
                "movdqu 6*16(%[src]), %%xmm13\n\t" /* Get block 7.      */
                "pxor %%xmm14, %%xmm3\n\t"         /* EncCTR-3 ^= input */
                "movdqu 7*16(%[src]), %%xmm14\n\t" /* Get block 8.      */
                "pxor %%xmm15, %%xmm4\n\t"         /* EncCTR-4 ^= input */
                "movdqu %%xmm0, 0*16(%[dst])\n\t"  /* Store block 1     */
                "pxor %%xmm1,  %%xmm8\n\t"         /* EncCTR-5 ^= input */
                "movdqu %%xmm0, 0*16(%[dst])\n\t"  /* Store block 1     */
                "pxor %%xmm12, %%xmm9\n\t"         /* EncCTR-6 ^= input */
                "movdqu %%xmm2, 1*16(%[dst])\n\t"  /* Store block 2.    */
                "pxor %%xmm13, %%xmm10\n\t"        /* EncCTR-7 ^= input */
                "movdqu %%xmm3, 2*16(%[dst])\n\t"  /* Store block 3.    */
                "pxor %%xmm14, %%xmm11\n\t"        /* EncCTR-8 ^= input */
                "movdqu %%xmm4, 3*16(%[dst])\n\t"  /* Store block 4.    */
                "movdqu %%xmm8, 4*16(%[dst])\n\t"  /* Store block 8.    */
                "movdqu %%xmm9, 5*16(%[dst])\n\t"  /* Store block 9.    */
                "movdqu %%xmm10, 6*16(%[dst])\n\t" /* Store block 10.   */
                "movdqu %%xmm11, 7*16(%[dst])\n\t" /* Store block 11.   */
                :
                : [src] "r" (a),
                  [dst] "r" (b)
                : "memory");
}

#endif /* __x86_64__ */


unsigned int
_gcry_aes_aesni_encrypt (const RIJNDAEL_context *ctx, unsigned char *dst,
                         const unsigned char *src)
{
  aesni_prepare ();
  asm volatile ("movdqu %[src], %%xmm0\n\t"
                :
                : [src] "m" (*src)
                : "memory" );
  do_aesni_enc (ctx);
  asm volatile ("movdqu %%xmm0, %[dst]\n\t"
                : [dst] "=m" (*dst)
                :
                : "memory" );
  aesni_cleanup ();
  return 0;
}


void
_gcry_aes_aesni_cfb_enc (RIJNDAEL_context *ctx, unsigned char *outbuf,
                         const unsigned char *inbuf, unsigned char *iv,
                         size_t nblocks)
{
  aesni_prepare ();

  asm volatile ("movdqu %[iv], %%xmm0\n\t"
                : /* No output */
                : [iv] "m" (*iv)
                : "memory" );

  for ( ;nblocks; nblocks-- )
    {
      do_aesni_enc (ctx);

      asm volatile ("movdqu %[inbuf], %%xmm1\n\t"
                    "pxor %%xmm1, %%xmm0\n\t"
                    "movdqu %%xmm0, %[outbuf]\n\t"
                    : [outbuf] "=m" (*outbuf)
                    : [inbuf] "m" (*inbuf)
                    : "memory" );

      outbuf += BLOCKSIZE;
      inbuf  += BLOCKSIZE;
    }

  asm volatile ("movdqu %%xmm0, %[iv]\n\t"
                : [iv] "=m" (*iv)
                :
                : "memory" );

  aesni_cleanup ();
}


void
_gcry_aes_aesni_cbc_enc (RIJNDAEL_context *ctx, unsigned char *outbuf,
                         const unsigned char *inbuf, unsigned char *iv,
                         size_t nblocks, int cbc_mac)
{
  aesni_prepare_2_6_variable;

  aesni_prepare ();
  aesni_prepare_2_6();

  asm volatile ("movdqu %[iv], %%xmm5\n\t"
                : /* No output */
                : [iv] "m" (*iv)
                : "memory" );

  for ( ;nblocks; nblocks-- )
    {
      asm volatile ("movdqu %[inbuf], %%xmm0\n\t"
                    "pxor %%xmm5, %%xmm0\n\t"
                    : /* No output */
                    : [inbuf] "m" (*inbuf)
                    : "memory" );

      do_aesni_enc (ctx);

      asm volatile ("movdqa %%xmm0, %%xmm5\n\t"
                    "movdqu %%xmm0, %[outbuf]\n\t"
                    : [outbuf] "=m" (*outbuf)
                    :
                    : "memory" );

      inbuf += BLOCKSIZE;
      if (!cbc_mac)
        outbuf += BLOCKSIZE;
    }

  asm volatile ("movdqu %%xmm5, %[iv]\n\t"
                : [iv] "=m" (*iv)
                :
                : "memory" );

  aesni_cleanup ();
  aesni_cleanup_2_6 ();
}


void
_gcry_aes_aesni_ctr_enc (RIJNDAEL_context *ctx, unsigned char *outbuf,
                         const unsigned char *inbuf, unsigned char *ctr,
                         size_t nblocks)
{
  static const unsigned char be_mask[16] __attribute__ ((aligned (16))) =
    { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  aesni_prepare_2_6_variable;

  aesni_prepare ();
  aesni_prepare_2_6();

  asm volatile ("movdqa %[mask], %%xmm6\n\t" /* Preload mask */
                "movdqa %[ctr], %%xmm5\n\t"  /* Preload CTR */
                : /* No output */
                : [mask] "m" (*be_mask),
                  [ctr] "m" (*ctr)
                : "memory");

#ifdef __x86_64__
  if (nblocks >= 8)
    {
      aesni_prepare_7_15_variable;

      aesni_prepare_7_15();

      for ( ;nblocks >= 8 ; nblocks -= 8 )
	{
	  do_aesni_ctr_8 (ctx, ctr, outbuf, inbuf);
	  outbuf += 8*BLOCKSIZE;
	  inbuf  += 8*BLOCKSIZE;
	}

      aesni_cleanup_7_15();
    }
#endif

  for ( ;nblocks >= 4 ; nblocks -= 4 )
    {
      do_aesni_ctr_4 (ctx, ctr, outbuf, inbuf);
      outbuf += 4*BLOCKSIZE;
      inbuf  += 4*BLOCKSIZE;
    }
  for ( ;nblocks; nblocks-- )
    {
      do_aesni_ctr (ctx, ctr, outbuf, inbuf);
      outbuf += BLOCKSIZE;
      inbuf  += BLOCKSIZE;
    }
  aesni_cleanup ();
  aesni_cleanup_2_6 ();
}


unsigned int
_gcry_aes_aesni_decrypt (const RIJNDAEL_context *ctx, unsigned char *dst,
                         const unsigned char *src)
{
  aesni_prepare ();
  asm volatile ("movdqu %[src], %%xmm0\n\t"
                :
                : [src] "m" (*src)
                : "memory" );
  do_aesni_dec (ctx);
  asm volatile ("movdqu %%xmm0, %[dst]\n\t"
                : [dst] "=m" (*dst)
                :
                : "memory" );
  aesni_cleanup ();
  return 0;
}


void
_gcry_aes_aesni_cfb_dec (RIJNDAEL_context *ctx, unsigned char *outbuf,
                         const unsigned char *inbuf, unsigned char *iv,
                         size_t nblocks)
{
  aesni_prepare_2_6_variable;

  aesni_prepare ();
  aesni_prepare_2_6();

  asm volatile ("movdqu %[iv], %%xmm6\n\t"
                : /* No output */
                : [iv] "m" (*iv)
                : "memory" );

  /* CFB decryption can be parallelized */

#ifdef __x86_64__
  if (nblocks >= 8)
    {
      aesni_prepare_7_15_variable;

      aesni_prepare_7_15();

      for ( ;nblocks >= 8; nblocks -= 8)
	{
	  asm volatile
	    ("movdqu %%xmm6,         %%xmm1\n\t" /* load input blocks */
	     "movdqu 0*16(%[inbuf]), %%xmm2\n\t"
	     "movdqu 1*16(%[inbuf]), %%xmm3\n\t"
	     "movdqu 2*16(%[inbuf]), %%xmm4\n\t"
	     "movdqu 3*16(%[inbuf]), %%xmm8\n\t"
	     "movdqu 4*16(%[inbuf]), %%xmm9\n\t"
	     "movdqu 5*16(%[inbuf]), %%xmm10\n\t"
	     "movdqu 6*16(%[inbuf]), %%xmm11\n\t"

	     "movdqu 7*16(%[inbuf]), %%xmm6\n\t" /* update IV */

	     "movdqa %%xmm2, %%xmm12\n\t"
	     "movdqa %%xmm3, %%xmm13\n\t"
	     "movdqa %%xmm4, %%xmm14\n\t"
	     "movdqa %%xmm8, %%xmm15\n\t"
	     : /* No output */
	     : [inbuf] "r" (inbuf)
	     : "memory");

	  do_aesni_enc_vec8 (ctx);

	  asm volatile
	    (
	     "pxor %%xmm12, %%xmm1\n\t"
	     "movdqu 4*16(%[inbuf]), %%xmm12\n\t"
	     "pxor %%xmm13, %%xmm2\n\t"
	     "movdqu 5*16(%[inbuf]), %%xmm13\n\t"
	     "pxor %%xmm14, %%xmm3\n\t"
	     "movdqu 6*16(%[inbuf]), %%xmm14\n\t"
	     "pxor %%xmm15, %%xmm4\n\t"
	     "movdqu 7*16(%[inbuf]), %%xmm15\n\t"

	     "pxor %%xmm12, %%xmm8\n\t"
	     "movdqu %%xmm1, 0*16(%[outbuf])\n\t"
	     "pxor %%xmm13, %%xmm9\n\t"
	     "movdqu %%xmm2, 1*16(%[outbuf])\n\t"
	     "pxor %%xmm14, %%xmm10\n\t"
	     "movdqu %%xmm3, 2*16(%[outbuf])\n\t"
	     "pxor %%xmm15, %%xmm11\n\t"
	     "movdqu %%xmm4, 3*16(%[outbuf])\n\t"

	     "movdqu %%xmm8, 4*16(%[outbuf])\n\t"
	     "movdqu %%xmm9, 5*16(%[outbuf])\n\t"
	     "movdqu %%xmm10, 6*16(%[outbuf])\n\t"
	     "movdqu %%xmm11, 7*16(%[outbuf])\n\t"

	     : /* No output */
	     : [inbuf] "r" (inbuf),
	       [outbuf] "r" (outbuf)
	     : "memory");

	  outbuf += 8*BLOCKSIZE;
	  inbuf  += 8*BLOCKSIZE;
	}

      aesni_cleanup_7_15();
    }
#endif

  for ( ;nblocks >= 4; nblocks -= 4)
    {
      asm volatile
        ("movdqu %%xmm6,         %%xmm1\n\t" /* load input blocks */
         "movdqu 0*16(%[inbuf]), %%xmm2\n\t"
         "movdqu 1*16(%[inbuf]), %%xmm3\n\t"
         "movdqu 2*16(%[inbuf]), %%xmm4\n\t"

         "movdqu 3*16(%[inbuf]), %%xmm6\n\t" /* update IV */
         : /* No output */
         : [inbuf] "r" (inbuf)
         : "memory");

      do_aesni_enc_vec4 (ctx);

      asm volatile
        ("movdqu 0*16(%[inbuf]), %%xmm5\n\t"
         "pxor %%xmm5, %%xmm1\n\t"
         "movdqu %%xmm1, 0*16(%[outbuf])\n\t"

         "movdqu 1*16(%[inbuf]), %%xmm5\n\t"
         "pxor %%xmm5, %%xmm2\n\t"
         "movdqu %%xmm2, 1*16(%[outbuf])\n\t"

         "movdqu 2*16(%[inbuf]), %%xmm5\n\t"
         "pxor %%xmm5, %%xmm3\n\t"
         "movdqu %%xmm3, 2*16(%[outbuf])\n\t"

         "movdqu 3*16(%[inbuf]), %%xmm5\n\t"
         "pxor %%xmm5, %%xmm4\n\t"
         "movdqu %%xmm4, 3*16(%[outbuf])\n\t"

         : /* No output */
         : [inbuf] "r" (inbuf),
           [outbuf] "r" (outbuf)
         : "memory");

      outbuf += 4*BLOCKSIZE;
      inbuf  += 4*BLOCKSIZE;
    }

  asm volatile ("movdqu %%xmm6, %%xmm0\n\t" ::: "cc");

  for ( ;nblocks; nblocks-- )
    {
      do_aesni_enc (ctx);

      asm volatile ("movdqa %%xmm0, %%xmm6\n\t"
                    "movdqu %[inbuf], %%xmm0\n\t"
                    "pxor %%xmm0, %%xmm6\n\t"
                    "movdqu %%xmm6, %[outbuf]\n\t"
                    : [outbuf] "=m" (*outbuf)
                    : [inbuf] "m" (*inbuf)
                    : "memory" );

      outbuf += BLOCKSIZE;
      inbuf  += BLOCKSIZE;
    }

  asm volatile ("movdqu %%xmm0, %[iv]\n\t"
                : [iv] "=m" (*iv)
                :
                : "memory" );

  aesni_cleanup ();
  aesni_cleanup_2_6 ();
}


void
_gcry_aes_aesni_cbc_dec (RIJNDAEL_context *ctx, unsigned char *outbuf,
			 const unsigned char *inbuf, unsigned char *iv,
			 size_t nblocks)
{
  aesni_prepare_2_6_variable;

  aesni_prepare ();
  aesni_prepare_2_6();

  asm volatile
    ("movdqu %[iv], %%xmm5\n\t"	/* use xmm5 as fast IV storage */
     : /* No output */
     : [iv] "m" (*iv)
     : "memory");

#ifdef __x86_64__
  if (nblocks >= 8)
    {
      aesni_prepare_7_15_variable;

      aesni_prepare_7_15();

      for ( ;nblocks >= 8 ; nblocks -= 8 )
	{
	  asm volatile
	    ("movdqu 0*16(%[inbuf]), %%xmm1\n\t"	/* load input blocks */
	     "movdqu 1*16(%[inbuf]), %%xmm2\n\t"
	     "movdqu 2*16(%[inbuf]), %%xmm3\n\t"
	     "movdqu 3*16(%[inbuf]), %%xmm4\n\t"
	     "movdqu 4*16(%[inbuf]), %%xmm8\n\t"
	     "movdqu 5*16(%[inbuf]), %%xmm9\n\t"
	     "movdqu 6*16(%[inbuf]), %%xmm10\n\t"
	     "movdqu 7*16(%[inbuf]), %%xmm11\n\t"

	     "movdqa %%xmm1, %%xmm12\n\t"
	     "movdqa %%xmm2, %%xmm13\n\t"
	     "movdqa %%xmm3, %%xmm14\n\t"
	     "movdqa %%xmm4, %%xmm15\n\t"

	     : /* No output */
	     : [inbuf] "r" (inbuf)
	     : "memory");

	  do_aesni_dec_vec8 (ctx);

	  asm volatile
	    ("pxor %%xmm5, %%xmm1\n\t"		/* xor IV with output */

	     "pxor %%xmm12, %%xmm2\n\t"		/* xor IV with output */
	     "movdqu 4*16(%[inbuf]), %%xmm12\n\t"

	     "pxor %%xmm13, %%xmm3\n\t"		/* xor IV with output */
	     "movdqu 5*16(%[inbuf]), %%xmm13\n\t"

	     "pxor %%xmm14, %%xmm4\n\t"		/* xor IV with output */
	     "movdqu 6*16(%[inbuf]), %%xmm14\n\t"

	     "pxor %%xmm15, %%xmm8\n\t"		/* xor IV with output */
	     "movdqu 7*16(%[inbuf]), %%xmm5\n\t"
	     "pxor %%xmm12, %%xmm9\n\t"		/* xor IV with output */
	     "movdqu %%xmm1, 0*16(%[outbuf])\n\t"
	     "pxor %%xmm13, %%xmm10\n\t"		/* xor IV with output */
	     "movdqu %%xmm2, 1*16(%[outbuf])\n\t"
	     "pxor %%xmm14, %%xmm11\n\t"		/* xor IV with output */
	     "movdqu %%xmm3, 2*16(%[outbuf])\n\t"
	     "movdqu %%xmm4, 3*16(%[outbuf])\n\t"
	     "movdqu %%xmm8, 4*16(%[outbuf])\n\t"
	     "movdqu %%xmm9, 5*16(%[outbuf])\n\t"
	     "movdqu %%xmm10, 6*16(%[outbuf])\n\t"
	     "movdqu %%xmm11, 7*16(%[outbuf])\n\t"

	     : /* No output */
	     : [inbuf] "r" (inbuf),
	       [outbuf] "r" (outbuf)
	     : "memory");

	  outbuf += 8*BLOCKSIZE;
	  inbuf  += 8*BLOCKSIZE;
	}

      aesni_cleanup_7_15();
    }
#endif

  for ( ;nblocks >= 4 ; nblocks -= 4 )
    {
      asm volatile
        ("movdqu 0*16(%[inbuf]), %%xmm1\n\t"	/* load input blocks */
         "movdqu 1*16(%[inbuf]), %%xmm2\n\t"
         "movdqu 2*16(%[inbuf]), %%xmm3\n\t"
         "movdqu 3*16(%[inbuf]), %%xmm4\n\t"
         : /* No output */
         : [inbuf] "r" (inbuf)
         : "memory");

      do_aesni_dec_vec4 (ctx);

      asm volatile
        ("pxor %%xmm5, %%xmm1\n\t"		/* xor IV with output */
         "movdqu 0*16(%[inbuf]), %%xmm5\n\t"	/* load new IV */
         "movdqu %%xmm1, 0*16(%[outbuf])\n\t"

         "pxor %%xmm5, %%xmm2\n\t"		/* xor IV with output */
         "movdqu 1*16(%[inbuf]), %%xmm5\n\t"	/* load new IV */
         "movdqu %%xmm2, 1*16(%[outbuf])\n\t"

         "pxor %%xmm5, %%xmm3\n\t"		/* xor IV with output */
         "movdqu 2*16(%[inbuf]), %%xmm5\n\t"	/* load new IV */
         "movdqu %%xmm3, 2*16(%[outbuf])\n\t"

         "pxor %%xmm5, %%xmm4\n\t"		/* xor IV with output */
         "movdqu 3*16(%[inbuf]), %%xmm5\n\t"	/* load new IV */
         "movdqu %%xmm4, 3*16(%[outbuf])\n\t"

         : /* No output */
         : [inbuf] "r" (inbuf),
           [outbuf] "r" (outbuf)
         : "memory");

      outbuf += 4*BLOCKSIZE;
      inbuf  += 4*BLOCKSIZE;
    }

  for ( ;nblocks; nblocks-- )
    {
      asm volatile
        ("movdqu %[inbuf], %%xmm0\n\t"
         "movdqa %%xmm0, %%xmm2\n\t"    /* use xmm2 as savebuf */
         : /* No output */
         : [inbuf] "m" (*inbuf)
         : "memory");

      /* uses only xmm0 and xmm1 */
      do_aesni_dec (ctx);

      asm volatile
        ("pxor %%xmm5, %%xmm0\n\t"	/* xor IV with output */
         "movdqu %%xmm0, %[outbuf]\n\t"
         "movdqu %%xmm2, %%xmm5\n\t"	/* store savebuf as new IV */
         : [outbuf] "=m" (*outbuf)
         :
         : "memory");

      outbuf += BLOCKSIZE;
      inbuf  += BLOCKSIZE;
    }

  asm volatile
    ("movdqu %%xmm5, %[iv]\n\t"	/* store IV */
     : /* No output */
     : [iv] "m" (*iv)
     : "memory");

  aesni_cleanup ();
  aesni_cleanup_2_6 ();
}


static void
aesni_ocb_enc (gcry_cipher_hd_t c, void *outbuf_arg,
               const void *inbuf_arg, size_t nblocks)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  u64 n = c->u_mode.ocb.data_nblocks;
  const unsigned char *l;
  aesni_prepare_2_6_variable;

  aesni_prepare ();
  aesni_prepare_2_6 ();

  /* Preload Offset and Checksum */
  asm volatile ("movdqu %[iv], %%xmm5\n\t"
                "movdqu %[ctr], %%xmm6\n\t"
                : /* No output */
                : [iv] "m" (*c->u_iv.iv),
                  [ctr] "m" (*c->u_ctr.ctr)
                : "memory" );


  for ( ;nblocks && n % 4; nblocks-- )
    {
      l = ocb_get_l(c, ++n);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* Checksum_i = Checksum_{i-1} xor P_i  */
      /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
      asm volatile ("movdqu %[l],     %%xmm1\n\t"
                    "movdqu %[inbuf], %%xmm0\n\t"
                    "pxor   %%xmm1,   %%xmm5\n\t"
                    "pxor   %%xmm0,   %%xmm6\n\t"
                    "pxor   %%xmm5,   %%xmm0\n\t"
                    :
                    : [l] "m" (*l),
                      [inbuf] "m" (*inbuf)
                    : "memory" );

      do_aesni_enc (ctx);

      asm volatile ("pxor   %%xmm5, %%xmm0\n\t"
                    "movdqu %%xmm0, %[outbuf]\n\t"
                    : [outbuf] "=m" (*outbuf)
                    :
                    : "memory" );

      inbuf += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

#ifdef __x86_64__
  if (nblocks >= 8)
    {
      aesni_prepare_7_15_variable;

      aesni_prepare_7_15();

      asm volatile ("movdqu %[l0], %%xmm7\n\t"
		    :
		    : [l0] "m" (*c->u_mode.ocb.L[0])
		    : "memory" );

      for ( ;nblocks >= 8 ; nblocks -= 8 )
	{
	  n += 4;
	  l = ocb_get_l(c, n);

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  /* Checksum_i = Checksum_{i-1} xor P_i  */
	  /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */

	  asm volatile ("movdqu %[l1],     %%xmm10\n\t"
			"movdqu %[inbuf0], %%xmm1\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm1,    %%xmm6\n\t"
			"pxor   %%xmm5,    %%xmm1\n\t"
			"movdqa %%xmm5,    %%xmm12\n\t"
			:
			: [l1] "m" (*c->u_mode.ocb.L[1]),
			  [inbuf0] "m" (*(inbuf + 0 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[inbuf1], %%xmm2\n\t"
			"pxor   %%xmm10,   %%xmm5\n\t"
			"pxor   %%xmm2,    %%xmm6\n\t"
			"pxor   %%xmm5,    %%xmm2\n\t"
			"movdqa %%xmm5,    %%xmm13\n\t"
			:
			: [inbuf1] "m" (*(inbuf + 1 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[inbuf2], %%xmm3\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm3,    %%xmm6\n\t"
			"pxor   %%xmm5,    %%xmm3\n\t"
			"movdqa %%xmm5,    %%xmm14\n\t"
			:
			: [inbuf2] "m" (*(inbuf + 2 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[l3],     %%xmm15\n\t"
			"movdqu %[inbuf3], %%xmm4\n\t"
			"pxor   %%xmm15,   %%xmm5\n\t"
			"pxor   %%xmm4,    %%xmm6\n\t"
			"pxor   %%xmm5,    %%xmm4\n\t"
			"movdqa %%xmm5,    %%xmm15\n\t"
			:
			: [l3] "m" (*l),
			  [inbuf3] "m" (*(inbuf + 3 * BLOCKSIZE))
			: "memory" );

	  n += 4;
	  l = ocb_get_l(c, n);

	  asm volatile ("movdqu %[inbuf4], %%xmm8\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm8,    %%xmm6\n\t"
			"pxor   %%xmm5,    %%xmm8\n\t"
			"movdqu %%xmm5,    %[outbuf4]\n\t"
			: [outbuf4] "=m" (*(outbuf + 4 * BLOCKSIZE))
			: [inbuf4] "m" (*(inbuf + 4 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[inbuf5], %%xmm9\n\t"
			"pxor   %%xmm10,   %%xmm5\n\t"
			"pxor   %%xmm9,    %%xmm6\n\t"
			"pxor   %%xmm5,    %%xmm9\n\t"
			"movdqu %%xmm5,    %[outbuf5]\n\t"
			: [outbuf5] "=m" (*(outbuf + 5 * BLOCKSIZE))
			: [inbuf5] "m" (*(inbuf + 5 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[inbuf6], %%xmm10\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm10,   %%xmm6\n\t"
			"pxor   %%xmm5,    %%xmm10\n\t"
			"movdqu %%xmm5,    %[outbuf6]\n\t"
			: [outbuf6] "=m" (*(outbuf + 6 * BLOCKSIZE))
			: [inbuf6] "m" (*(inbuf + 6 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[l7],     %%xmm11\n\t"
			"pxor   %%xmm11,   %%xmm5\n\t"
			"movdqu %[inbuf7], %%xmm11\n\t"
			"pxor   %%xmm11,   %%xmm6\n\t"
			"pxor   %%xmm5,    %%xmm11\n\t"
			:
			: [l7] "m" (*l),
			  [inbuf7] "m" (*(inbuf + 7 * BLOCKSIZE))
			: "memory" );

	  do_aesni_enc_vec8 (ctx);

	  asm volatile ("pxor   %%xmm12,   %%xmm1\n\t"
			"pxor   %%xmm13,   %%xmm2\n\t"
			"movdqu %[outbuf4],%%xmm0\n\t"
			"movdqu %[outbuf5],%%xmm12\n\t"
			"movdqu %[outbuf6],%%xmm13\n\t"
			"pxor   %%xmm14,   %%xmm3\n\t"
			"pxor   %%xmm15,   %%xmm4\n\t"
			"pxor   %%xmm0,    %%xmm8\n\t"
			"pxor   %%xmm12,   %%xmm9\n\t"
			"pxor   %%xmm13,   %%xmm10\n\t"
			"pxor   %%xmm5,    %%xmm11\n\t"
			"movdqu %%xmm1,    %[outbuf0]\n\t"
			"movdqu %%xmm2,    %[outbuf1]\n\t"
			"movdqu %%xmm3,    %[outbuf2]\n\t"
			"movdqu %%xmm4,    %[outbuf3]\n\t"
			"movdqu %%xmm8,    %[outbuf4]\n\t"
			"movdqu %%xmm9,    %[outbuf5]\n\t"
			"movdqu %%xmm10,   %[outbuf6]\n\t"
			"movdqu %%xmm11,   %[outbuf7]\n\t"
			: [outbuf0] "=m" (*(outbuf + 0 * BLOCKSIZE)),
			  [outbuf1] "=m" (*(outbuf + 1 * BLOCKSIZE)),
			  [outbuf2] "=m" (*(outbuf + 2 * BLOCKSIZE)),
			  [outbuf3] "=m" (*(outbuf + 3 * BLOCKSIZE)),
			  [outbuf4] "+m" (*(outbuf + 4 * BLOCKSIZE)),
			  [outbuf5] "+m" (*(outbuf + 5 * BLOCKSIZE)),
			  [outbuf6] "+m" (*(outbuf + 6 * BLOCKSIZE)),
			  [outbuf7] "=m" (*(outbuf + 7 * BLOCKSIZE))
			:
			: "memory" );

	  outbuf += 8*BLOCKSIZE;
	  inbuf  += 8*BLOCKSIZE;
	}

    aesni_cleanup_7_15();
  }
#endif

  for ( ;nblocks >= 4 ; nblocks -= 4 )
    {
      n += 4;
      l = ocb_get_l(c, n);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* Checksum_i = Checksum_{i-1} xor P_i  */
      /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
      asm volatile ("movdqu %[l0],     %%xmm4\n\t"
		    "movdqu %[inbuf0], %%xmm1\n\t"
		    "pxor   %%xmm4,    %%xmm5\n\t"
		    "pxor   %%xmm1,    %%xmm6\n\t"
		    "pxor   %%xmm5,    %%xmm1\n\t"
		    "movdqu %%xmm5,    %[outbuf0]\n\t"
		    : [outbuf0] "=m" (*(outbuf + 0 * BLOCKSIZE))
		    : [l0] "m" (*c->u_mode.ocb.L[0]),
		      [inbuf0] "m" (*(inbuf + 0 * BLOCKSIZE))
		    : "memory" );
      asm volatile ("movdqu %[l1],     %%xmm0\n\t"
		    "movdqu %[inbuf1], %%xmm2\n\t"
		    "pxor   %%xmm0,    %%xmm5\n\t"
		    "pxor   %%xmm2,    %%xmm6\n\t"
		    "pxor   %%xmm5,    %%xmm2\n\t"
		    "movdqu %%xmm5,    %[outbuf1]\n\t"
		    : [outbuf1] "=m" (*(outbuf + 1 * BLOCKSIZE))
		    : [l1] "m" (*c->u_mode.ocb.L[1]),
		      [inbuf1] "m" (*(inbuf + 1 * BLOCKSIZE))
		    : "memory" );
      asm volatile ("movdqu %[inbuf2], %%xmm3\n\t"
		    "pxor   %%xmm4,    %%xmm5\n\t"
		    "pxor   %%xmm3,    %%xmm6\n\t"
		    "pxor   %%xmm5,    %%xmm3\n\t"
		    "movdqu %%xmm5,    %[outbuf2]\n\t"
		    : [outbuf2] "=m" (*(outbuf + 2 * BLOCKSIZE))
		    : [inbuf2] "m" (*(inbuf + 2 * BLOCKSIZE))
		    : "memory" );
      asm volatile ("movdqu %[l3],     %%xmm4\n\t"
		    "pxor   %%xmm4,    %%xmm5\n\t"
		    "movdqu %[inbuf3], %%xmm4\n\t"
		    "pxor   %%xmm4,    %%xmm6\n\t"
		    "pxor   %%xmm5,    %%xmm4\n\t"
		    :
		    : [l3] "m" (*l),
		      [inbuf3] "m" (*(inbuf + 3 * BLOCKSIZE))
		    : "memory" );

      do_aesni_enc_vec4 (ctx);

      asm volatile ("movdqu %[outbuf0],%%xmm0\n\t"
		    "pxor   %%xmm0,    %%xmm1\n\t"
		    "movdqu %%xmm1,    %[outbuf0]\n\t"
		    "movdqu %[outbuf1],%%xmm0\n\t"
		    "pxor   %%xmm0,    %%xmm2\n\t"
		    "movdqu %%xmm2,    %[outbuf1]\n\t"
		    "movdqu %[outbuf2],%%xmm0\n\t"
		    "pxor   %%xmm0,    %%xmm3\n\t"
		    "movdqu %%xmm3,    %[outbuf2]\n\t"
		    "pxor   %%xmm5,    %%xmm4\n\t"
		    "movdqu %%xmm4,    %[outbuf3]\n\t"
		    : [outbuf0] "+m" (*(outbuf + 0 * BLOCKSIZE)),
		      [outbuf1] "+m" (*(outbuf + 1 * BLOCKSIZE)),
		      [outbuf2] "+m" (*(outbuf + 2 * BLOCKSIZE)),
		      [outbuf3] "=m" (*(outbuf + 3 * BLOCKSIZE))
		    :
		    : "memory" );

      outbuf += 4*BLOCKSIZE;
      inbuf  += 4*BLOCKSIZE;
    }

  for ( ;nblocks; nblocks-- )
    {
      l = ocb_get_l(c, ++n);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* Checksum_i = Checksum_{i-1} xor P_i  */
      /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
      asm volatile ("movdqu %[l],     %%xmm1\n\t"
                    "movdqu %[inbuf], %%xmm0\n\t"
                    "pxor   %%xmm1,   %%xmm5\n\t"
                    "pxor   %%xmm0,   %%xmm6\n\t"
                    "pxor   %%xmm5,   %%xmm0\n\t"
                    :
                    : [l] "m" (*l),
                      [inbuf] "m" (*inbuf)
                    : "memory" );

      do_aesni_enc (ctx);

      asm volatile ("pxor   %%xmm5, %%xmm0\n\t"
                    "movdqu %%xmm0, %[outbuf]\n\t"
                    : [outbuf] "=m" (*outbuf)
                    :
                    : "memory" );

      inbuf += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  c->u_mode.ocb.data_nblocks = n;
  asm volatile ("movdqu %%xmm5, %[iv]\n\t"
                "movdqu %%xmm6, %[ctr]\n\t"
                : [iv] "=m" (*c->u_iv.iv),
                  [ctr] "=m" (*c->u_ctr.ctr)
                :
                : "memory" );

  aesni_cleanup ();
  aesni_cleanup_2_6 ();
}


static void
aesni_ocb_dec (gcry_cipher_hd_t c, void *outbuf_arg,
               const void *inbuf_arg, size_t nblocks)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  u64 n = c->u_mode.ocb.data_nblocks;
  const unsigned char *l;
  aesni_prepare_2_6_variable;

  aesni_prepare ();
  aesni_prepare_2_6 ();

  /* Preload Offset and Checksum */
  asm volatile ("movdqu %[iv], %%xmm5\n\t"
                "movdqu %[ctr], %%xmm6\n\t"
                : /* No output */
                : [iv] "m" (*c->u_iv.iv),
                  [ctr] "m" (*c->u_ctr.ctr)
                : "memory" );

  for ( ;nblocks && n % 4; nblocks-- )
    {
      l = ocb_get_l(c, ++n);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)  */
      /* Checksum_i = Checksum_{i-1} xor P_i  */
      asm volatile ("movdqu %[l],     %%xmm1\n\t"
                    "movdqu %[inbuf], %%xmm0\n\t"
                    "pxor   %%xmm1,   %%xmm5\n\t"
                    "pxor   %%xmm5,   %%xmm0\n\t"
                    :
                    : [l] "m" (*l),
                      [inbuf] "m" (*inbuf)
                    : "memory" );

      do_aesni_dec (ctx);

      asm volatile ("pxor   %%xmm5, %%xmm0\n\t"
                    "pxor   %%xmm0, %%xmm6\n\t"
                    "movdqu %%xmm0, %[outbuf]\n\t"
                    : [outbuf] "=m" (*outbuf)
                    :
                    : "memory" );

      inbuf += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

#ifdef __x86_64__
  if (nblocks >= 8)
    {
      aesni_prepare_7_15_variable;

      aesni_prepare_7_15();

      asm volatile ("movdqu %[l0], %%xmm7\n\t"
		    :
		    : [l0] "m" (*c->u_mode.ocb.L[0])
		    : "memory" );

      for ( ;nblocks >= 8 ; nblocks -= 8 )
	{
	  n += 4;
	  l = ocb_get_l(c, n);

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)  */
	  /* Checksum_i = Checksum_{i-1} xor P_i  */

	  asm volatile ("movdqu %[l1],     %%xmm10\n\t"
			"movdqu %[inbuf0], %%xmm1\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm1\n\t"
			"movdqa %%xmm5,    %%xmm12\n\t"
			:
			: [l1] "m" (*c->u_mode.ocb.L[1]),
			  [inbuf0] "m" (*(inbuf + 0 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[inbuf1], %%xmm2\n\t"
			"pxor   %%xmm10,   %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm2\n\t"
			"movdqa %%xmm5,    %%xmm13\n\t"
			:
			: [inbuf1] "m" (*(inbuf + 1 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[inbuf2], %%xmm3\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm3\n\t"
			"movdqa %%xmm5,    %%xmm14\n\t"
			:
			: [inbuf2] "m" (*(inbuf + 2 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[l3],     %%xmm0\n\t"
			"movdqu %[inbuf3], %%xmm4\n\t"
			"pxor   %%xmm0,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm4\n\t"
			"movdqa %%xmm5,    %%xmm15\n\t"
			:
			: [l3] "m" (*l),
			  [inbuf3] "m" (*(inbuf + 3 * BLOCKSIZE))
			: "memory" );

	  n += 4;
	  l = ocb_get_l(c, n);

	  asm volatile ("movdqu %[inbuf4], %%xmm8\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm8\n\t"
			"movdqu %%xmm5,    %[outbuf4]\n\t"
			: [outbuf4] "=m" (*(outbuf + 4 * BLOCKSIZE))
			: [inbuf4] "m" (*(inbuf + 4 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[inbuf5], %%xmm9\n\t"
			"pxor   %%xmm10,   %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm9\n\t"
			"movdqu %%xmm5,    %[outbuf5]\n\t"
			: [outbuf5] "=m" (*(outbuf + 5 * BLOCKSIZE))
			: [inbuf5] "m" (*(inbuf + 5 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[inbuf6], %%xmm10\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm10\n\t"
			"movdqu %%xmm5,    %[outbuf6]\n\t"
			: [outbuf6] "=m" (*(outbuf + 6 * BLOCKSIZE))
			: [inbuf6] "m" (*(inbuf + 6 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[l7],     %%xmm0\n\t"
			"movdqu %[inbuf7], %%xmm11\n\t"
			"pxor   %%xmm0,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm11\n\t"
			:
			: [l7] "m" (*l),
			  [inbuf7] "m" (*(inbuf + 7 * BLOCKSIZE))
			: "memory" );

	  do_aesni_dec_vec8 (ctx);

	  asm volatile ("pxor   %%xmm12,   %%xmm1\n\t"
			"pxor   %%xmm13,   %%xmm2\n\t"
			"movdqu %[outbuf4],%%xmm0\n\t"
			"movdqu %[outbuf5],%%xmm12\n\t"
			"movdqu %[outbuf6],%%xmm13\n\t"
			"pxor   %%xmm14,   %%xmm3\n\t"
			"pxor   %%xmm15,   %%xmm4\n\t"
			"pxor   %%xmm0,    %%xmm8\n\t"
			"pxor   %%xmm12,   %%xmm9\n\t"
			"pxor   %%xmm13,   %%xmm10\n\t"
			"pxor   %%xmm5,    %%xmm11\n\t"
			"movdqu %%xmm1,    %[outbuf0]\n\t"
			"movdqu %%xmm2,    %[outbuf1]\n\t"
			"movdqu %%xmm3,    %[outbuf2]\n\t"
			"movdqu %%xmm4,    %[outbuf3]\n\t"
			"movdqu %%xmm8,    %[outbuf4]\n\t"
			"movdqu %%xmm9,    %[outbuf5]\n\t"
			"movdqu %%xmm10,   %[outbuf6]\n\t"
			"movdqu %%xmm11,   %[outbuf7]\n\t"
			"pxor   %%xmm2,    %%xmm1\n\t"
			"pxor   %%xmm4,    %%xmm1\n\t"
			"pxor   %%xmm9,    %%xmm1\n\t"
			"pxor   %%xmm11,   %%xmm1\n\t"
			"pxor   %%xmm3,    %%xmm6\n\t"
			"pxor   %%xmm8,    %%xmm6\n\t"
			"pxor   %%xmm10,   %%xmm6\n\t"
			"pxor   %%xmm1,    %%xmm6\n\t"
			: [outbuf0] "=m" (*(outbuf + 0 * BLOCKSIZE)),
			  [outbuf1] "=m" (*(outbuf + 1 * BLOCKSIZE)),
			  [outbuf2] "=m" (*(outbuf + 2 * BLOCKSIZE)),
			  [outbuf3] "=m" (*(outbuf + 3 * BLOCKSIZE)),
			  [outbuf4] "+m" (*(outbuf + 4 * BLOCKSIZE)),
			  [outbuf5] "+m" (*(outbuf + 5 * BLOCKSIZE)),
			  [outbuf6] "+m" (*(outbuf + 6 * BLOCKSIZE)),
			  [outbuf7] "=m" (*(outbuf + 7 * BLOCKSIZE))
			:
			: "memory" );

	  outbuf += 8*BLOCKSIZE;
	  inbuf  += 8*BLOCKSIZE;
	}

      aesni_cleanup_7_15();
    }
#endif

  for ( ;nblocks >= 4 ; nblocks -= 4 )
    {
      n += 4;
      l = ocb_get_l(c, n);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)  */
      /* Checksum_i = Checksum_{i-1} xor P_i  */
      asm volatile ("movdqu %[l0],     %%xmm4\n\t"
		    "movdqu %[inbuf0], %%xmm1\n\t"
		    "pxor   %%xmm4,    %%xmm5\n\t"
		    "pxor   %%xmm5,    %%xmm1\n\t"
		    "movdqu %%xmm5,    %[outbuf0]\n\t"
		    : [outbuf0] "=m" (*(outbuf + 0 * BLOCKSIZE))
		    : [l0] "m" (*c->u_mode.ocb.L[0]),
		      [inbuf0] "m" (*(inbuf + 0 * BLOCKSIZE))
		    : "memory" );
      asm volatile ("movdqu %[l1],     %%xmm0\n\t"
		    "movdqu %[inbuf1], %%xmm2\n\t"
		    "pxor   %%xmm0,    %%xmm5\n\t"
		    "pxor   %%xmm5,    %%xmm2\n\t"
		    "movdqu %%xmm5,    %[outbuf1]\n\t"
		    : [outbuf1] "=m" (*(outbuf + 1 * BLOCKSIZE))
		    : [l1] "m" (*c->u_mode.ocb.L[1]),
		      [inbuf1] "m" (*(inbuf + 1 * BLOCKSIZE))
		    : "memory" );
      asm volatile ("movdqu %[inbuf2], %%xmm3\n\t"
		    "pxor   %%xmm4,    %%xmm5\n\t"
		    "pxor   %%xmm5,    %%xmm3\n\t"
		    "movdqu %%xmm5,    %[outbuf2]\n\t"
		    : [outbuf2] "=m" (*(outbuf + 2 * BLOCKSIZE))
		    : [inbuf2] "m" (*(inbuf + 2 * BLOCKSIZE))
		    : "memory" );
      asm volatile ("movdqu %[l3],     %%xmm0\n\t"
		    "movdqu %[inbuf3], %%xmm4\n\t"
		    "pxor   %%xmm0,    %%xmm5\n\t"
		    "pxor   %%xmm5,    %%xmm4\n\t"
		    :
		    : [l3] "m" (*l),
		      [inbuf3] "m" (*(inbuf + 3 * BLOCKSIZE))
		    : "memory" );

      do_aesni_dec_vec4 (ctx);

      asm volatile ("movdqu %[outbuf0],%%xmm0\n\t"
		    "pxor   %%xmm0,    %%xmm1\n\t"
		    "movdqu %%xmm1,    %[outbuf0]\n\t"
		    "movdqu %[outbuf1],%%xmm0\n\t"
		    "pxor   %%xmm0,    %%xmm2\n\t"
		    "movdqu %%xmm2,    %[outbuf1]\n\t"
		    "movdqu %[outbuf2],%%xmm0\n\t"
		    "pxor   %%xmm0,    %%xmm3\n\t"
		    "movdqu %%xmm3,    %[outbuf2]\n\t"
		    "pxor   %%xmm5,    %%xmm4\n\t"
		    "movdqu %%xmm4,    %[outbuf3]\n\t"
		    "pxor   %%xmm1,    %%xmm6\n\t"
		    "pxor   %%xmm2,    %%xmm6\n\t"
		    "pxor   %%xmm3,    %%xmm6\n\t"
		    "pxor   %%xmm4,    %%xmm6\n\t"
		    : [outbuf0] "+m" (*(outbuf + 0 * BLOCKSIZE)),
		      [outbuf1] "+m" (*(outbuf + 1 * BLOCKSIZE)),
		      [outbuf2] "+m" (*(outbuf + 2 * BLOCKSIZE)),
		      [outbuf3] "=m" (*(outbuf + 3 * BLOCKSIZE))
		    :
		    : "memory" );

      outbuf += 4*BLOCKSIZE;
      inbuf  += 4*BLOCKSIZE;
    }

  for ( ;nblocks; nblocks-- )
    {
      l = ocb_get_l(c, ++n);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)  */
      /* Checksum_i = Checksum_{i-1} xor P_i  */
      asm volatile ("movdqu %[l],     %%xmm1\n\t"
                    "movdqu %[inbuf], %%xmm0\n\t"
                    "pxor   %%xmm1,   %%xmm5\n\t"
                    "pxor   %%xmm5,   %%xmm0\n\t"
                    :
                    : [l] "m" (*l),
                      [inbuf] "m" (*inbuf)
                    : "memory" );

      do_aesni_dec (ctx);

      asm volatile ("pxor   %%xmm5, %%xmm0\n\t"
                    "pxor   %%xmm0, %%xmm6\n\t"
                    "movdqu %%xmm0, %[outbuf]\n\t"
                    : [outbuf] "=m" (*outbuf)
                    :
                    : "memory" );

      inbuf += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  c->u_mode.ocb.data_nblocks = n;
  asm volatile ("movdqu %%xmm5, %[iv]\n\t"
                "movdqu %%xmm6, %[ctr]\n\t"
                : [iv] "=m" (*c->u_iv.iv),
                  [ctr] "=m" (*c->u_ctr.ctr)
                :
                : "memory" );

  aesni_cleanup ();
  aesni_cleanup_2_6 ();
}


void
_gcry_aes_aesni_ocb_crypt(gcry_cipher_hd_t c, void *outbuf_arg,
                          const void *inbuf_arg, size_t nblocks, int encrypt)
{
  if (encrypt)
    aesni_ocb_enc(c, outbuf_arg, inbuf_arg, nblocks);
  else
    aesni_ocb_dec(c, outbuf_arg, inbuf_arg, nblocks);
}


void
_gcry_aes_aesni_ocb_auth (gcry_cipher_hd_t c, const void *abuf_arg,
                          size_t nblocks)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  const unsigned char *abuf = abuf_arg;
  u64 n = c->u_mode.ocb.aad_nblocks;
  const unsigned char *l;
  aesni_prepare_2_6_variable;

  aesni_prepare ();
  aesni_prepare_2_6 ();

  /* Preload Offset and Sum */
  asm volatile ("movdqu %[iv], %%xmm5\n\t"
                "movdqu %[ctr], %%xmm6\n\t"
                : /* No output */
                : [iv] "m" (*c->u_mode.ocb.aad_offset),
                  [ctr] "m" (*c->u_mode.ocb.aad_sum)
                : "memory" );

  for ( ;nblocks && n % 4; nblocks-- )
    {
      l = ocb_get_l(c, ++n);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
      asm volatile ("movdqu %[l],     %%xmm1\n\t"
                    "movdqu %[abuf],  %%xmm0\n\t"
                    "pxor   %%xmm1,   %%xmm5\n\t"
                    "pxor   %%xmm5,   %%xmm0\n\t"
                    :
                    : [l] "m" (*l),
                      [abuf] "m" (*abuf)
                    : "memory" );

      do_aesni_enc (ctx);

      asm volatile ("pxor   %%xmm0,   %%xmm6\n\t"
                    :
                    :
                    : "memory" );

      abuf += BLOCKSIZE;
    }

#ifdef __x86_64__
  if (nblocks >= 8)
    {
      aesni_prepare_7_15_variable;

      aesni_prepare_7_15();

      asm volatile ("movdqu %[l0], %%xmm7\n\t"
		    "movdqu %[l1], %%xmm12\n\t"
		    :
		    : [l0] "m" (*c->u_mode.ocb.L[0]),
		      [l1] "m" (*c->u_mode.ocb.L[1])
		    : "memory" );

      for ( ;nblocks >= 8 ; nblocks -= 8 )
	{
	  n += 4;
	  l = ocb_get_l(c, n);

	  /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
	  /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
	  asm volatile ("movdqu %[abuf0],  %%xmm1\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm1\n\t"
			:
			: [abuf0] "m" (*(abuf + 0 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[abuf1],  %%xmm2\n\t"
			"pxor   %%xmm12,   %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm2\n\t"
			:
			: [abuf1] "m" (*(abuf + 1 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[abuf2],  %%xmm3\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm3\n\t"
			:
			: [abuf2] "m" (*(abuf + 2 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[l3],     %%xmm0\n\t"
			"movdqu %[abuf3],  %%xmm4\n\t"
			"pxor   %%xmm0,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm4\n\t"
			:
			: [l3] "m" (*l),
			  [abuf3] "m" (*(abuf + 3 * BLOCKSIZE))
			: "memory" );

	  n += 4;
	  l = ocb_get_l(c, n);

	  asm volatile ("movdqu %[abuf4],  %%xmm8\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm8\n\t"
			:
			: [abuf4] "m" (*(abuf + 4 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[abuf5],  %%xmm9\n\t"
			"pxor   %%xmm12,   %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm9\n\t"
			:
			: [abuf5] "m" (*(abuf + 5 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[abuf6],  %%xmm10\n\t"
			"pxor   %%xmm7,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm10\n\t"
			:
			: [abuf6] "m" (*(abuf + 6 * BLOCKSIZE))
			: "memory" );
	  asm volatile ("movdqu %[l7],     %%xmm0\n\t"
			"movdqu %[abuf7],  %%xmm11\n\t"
			"pxor   %%xmm0,    %%xmm5\n\t"
			"pxor   %%xmm5,    %%xmm11\n\t"
			:
			: [l7] "m" (*l),
			  [abuf7] "m" (*(abuf + 7 * BLOCKSIZE))
			: "memory" );

	  do_aesni_enc_vec8 (ctx);

	  asm volatile ("pxor   %%xmm2,   %%xmm1\n\t"
			"pxor   %%xmm3,   %%xmm1\n\t"
			"pxor   %%xmm4,   %%xmm1\n\t"
			"pxor   %%xmm8,   %%xmm1\n\t"
			"pxor   %%xmm9,   %%xmm6\n\t"
			"pxor   %%xmm10,  %%xmm6\n\t"
			"pxor   %%xmm11,  %%xmm6\n\t"
			"pxor   %%xmm1,   %%xmm6\n\t"
			:
			:
			: "memory" );

	  abuf += 8*BLOCKSIZE;
	}

      aesni_cleanup_7_15();
    }
#endif

  for ( ;nblocks >= 4 ; nblocks -= 4 )
    {
      n += 4;
      l = ocb_get_l(c, n);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
      asm volatile ("movdqu %[l0],     %%xmm4\n\t"
		    "movdqu %[abuf0],  %%xmm1\n\t"
		    "pxor   %%xmm4,    %%xmm5\n\t"
		    "pxor   %%xmm5,    %%xmm1\n\t"
		    :
		    : [l0] "m" (*c->u_mode.ocb.L[0]),
		      [abuf0] "m" (*(abuf + 0 * BLOCKSIZE))
		    : "memory" );
      asm volatile ("movdqu %[l1],     %%xmm0\n\t"
		    "movdqu %[abuf1],  %%xmm2\n\t"
		    "pxor   %%xmm0,    %%xmm5\n\t"
		    "pxor   %%xmm5,    %%xmm2\n\t"
		    :
		    : [l1] "m" (*c->u_mode.ocb.L[1]),
		      [abuf1] "m" (*(abuf + 1 * BLOCKSIZE))
		    : "memory" );
      asm volatile ("movdqu %[abuf2],  %%xmm3\n\t"
		    "pxor   %%xmm4,    %%xmm5\n\t"
		    "pxor   %%xmm5,    %%xmm3\n\t"
		    :
		    : [l2] "m" (*c->u_mode.ocb.L[0]),
		      [abuf2] "m" (*(abuf + 2 * BLOCKSIZE))
		    : "memory" );
      asm volatile ("movdqu %[l3],     %%xmm0\n\t"
		    "movdqu %[abuf3],  %%xmm4\n\t"
		    "pxor   %%xmm0,    %%xmm5\n\t"
		    "pxor   %%xmm5,    %%xmm4\n\t"
		    :
		    : [l3] "m" (*l),
		      [abuf3] "m" (*(abuf + 3 * BLOCKSIZE))
		    : "memory" );

      do_aesni_enc_vec4 (ctx);

      asm volatile ("pxor   %%xmm1,   %%xmm6\n\t"
		    "pxor   %%xmm2,   %%xmm6\n\t"
		    "pxor   %%xmm3,   %%xmm6\n\t"
		    "pxor   %%xmm4,   %%xmm6\n\t"
		    :
		    :
		    : "memory" );

      abuf += 4*BLOCKSIZE;
    }

  for ( ;nblocks; nblocks-- )
    {
      l = ocb_get_l(c, ++n);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
      asm volatile ("movdqu %[l],     %%xmm1\n\t"
                    "movdqu %[abuf],  %%xmm0\n\t"
                    "pxor   %%xmm1,   %%xmm5\n\t"
                    "pxor   %%xmm5,   %%xmm0\n\t"
                    :
                    : [l] "m" (*l),
                      [abuf] "m" (*abuf)
                    : "memory" );

      do_aesni_enc (ctx);

      asm volatile ("pxor   %%xmm0,   %%xmm6\n\t"
                    :
                    :
                    : "memory" );

      abuf += BLOCKSIZE;
    }

  c->u_mode.ocb.aad_nblocks = n;
  asm volatile ("movdqu %%xmm5, %[iv]\n\t"
                "movdqu %%xmm6, %[ctr]\n\t"
                : [iv] "=m" (*c->u_mode.ocb.aad_offset),
                  [ctr] "=m" (*c->u_mode.ocb.aad_sum)
                :
                : "memory" );

  aesni_cleanup ();
  aesni_cleanup_2_6 ();
}


#endif /* USE_AESNI */
