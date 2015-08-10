/* SSSE3 vector permutation AES for Libgcrypt
 * Copyright (C) 2014-2015 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
 *
 *
 * The code is based on the public domain library libvpaes version 0.5
 * available at http://crypto.stanford.edu/vpaes/ and which carries
 * this notice:
 *
 *     libvpaes: constant-time SSSE3 AES encryption and decryption.
 *     version 0.5
 *
 *     By Mike Hamburg, Stanford University, 2009.  Public domain.
 *     I wrote essentially all of this code.  I did not write the test
 *     vectors; they are the NIST known answer tests.  I hereby release all
 *     the code and documentation here that I wrote into the public domain.
 *
 *     This is an implementation of AES following my paper,
 *       "Accelerating AES with Vector Permute Instructions"
 *       CHES 2009; http://shiftleft.org/papers/vector_aes/
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


#ifdef USE_SSSE3


#if _GCRY_GCC_VERSION >= 40400 /* 4.4 */
/* Prevent compiler from issuing SSE instructions between asm blocks. */
#  pragma GCC target("no-sse")
#endif


/* Two macros to be called prior and after the use of SSSE3
  instructions.  There should be no external function calls between
  the use of these macros.  There purpose is to make sure that the
  SSE registers are cleared and won't reveal any information about
  the key or the data.  */
#ifdef HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS
# define SSSE3_STATE_SIZE (16 * 10)
/* XMM6-XMM15 are callee-saved registers on WIN64. */
# define vpaes_ssse3_prepare() \
    asm volatile ("movdqu %%xmm6,  0*16(%0)\n\t" \
                  "movdqu %%xmm7,  1*16(%0)\n\t" \
                  "movdqu %%xmm8,  2*16(%0)\n\t" \
                  "movdqu %%xmm9,  3*16(%0)\n\t" \
                  "movdqu %%xmm10, 4*16(%0)\n\t" \
                  "movdqu %%xmm11, 5*16(%0)\n\t" \
                  "movdqu %%xmm12, 6*16(%0)\n\t" \
                  "movdqu %%xmm13, 7*16(%0)\n\t" \
                  "movdqu %%xmm14, 8*16(%0)\n\t" \
                  "movdqu %%xmm15, 9*16(%0)\n\t" \
                  : \
                  : "r" (ssse3_state) \
                  : "memory" )
# define vpaes_ssse3_cleanup() \
    asm volatile ("pxor	%%xmm0,  %%xmm0 \n\t" \
                  "pxor	%%xmm1,  %%xmm1 \n\t" \
                  "pxor	%%xmm2,  %%xmm2 \n\t" \
                  "pxor	%%xmm3,  %%xmm3 \n\t" \
                  "pxor	%%xmm4,  %%xmm4 \n\t" \
                  "pxor	%%xmm5,  %%xmm5 \n\t" \
                  "movdqu 0*16(%0), %%xmm6 \n\t" \
                  "movdqu 1*16(%0), %%xmm7 \n\t" \
                  "movdqu 2*16(%0), %%xmm8 \n\t" \
                  "movdqu 3*16(%0), %%xmm9 \n\t" \
                  "movdqu 4*16(%0), %%xmm10 \n\t" \
                  "movdqu 5*16(%0), %%xmm11 \n\t" \
                  "movdqu 6*16(%0), %%xmm12 \n\t" \
                  "movdqu 7*16(%0), %%xmm13 \n\t" \
                  "movdqu 8*16(%0), %%xmm14 \n\t" \
                  "movdqu 9*16(%0), %%xmm15 \n\t" \
                  : \
                  : "r" (ssse3_state) \
                  : "memory" )
#else
# define SSSE3_STATE_SIZE 1
# define vpaes_ssse3_prepare() (void)ssse3_state
# define vpaes_ssse3_cleanup() \
    asm volatile ("pxor	%%xmm0,  %%xmm0 \n\t" \
                  "pxor	%%xmm1,  %%xmm1 \n\t" \
                  "pxor	%%xmm2,  %%xmm2 \n\t" \
                  "pxor	%%xmm3,  %%xmm3 \n\t" \
                  "pxor	%%xmm4,  %%xmm4 \n\t" \
                  "pxor	%%xmm5,  %%xmm5 \n\t" \
                  "pxor	%%xmm6,  %%xmm6 \n\t" \
                  "pxor	%%xmm7,  %%xmm7 \n\t" \
                  "pxor	%%xmm8,  %%xmm8 \n\t" \
                  ::: "memory" )
#endif

#define vpaes_ssse3_prepare_enc(const_ptr) \
    vpaes_ssse3_prepare(); \
    asm volatile ("lea	.Laes_consts(%%rip), %q0 \n\t" \
                  "movdqa	          (%q0), %%xmm9  # 0F \n\t" \
                  "movdqa	.Lk_inv   (%q0), %%xmm10 # inv \n\t" \
                  "movdqa	.Lk_inv+16(%q0), %%xmm11 # inva \n\t" \
                  "movdqa	.Lk_sb1   (%q0), %%xmm13 # sb1u \n\t" \
                  "movdqa	.Lk_sb1+16(%q0), %%xmm12 # sb1t \n\t" \
                  "movdqa	.Lk_sb2   (%q0), %%xmm15 # sb2u \n\t" \
                  "movdqa	.Lk_sb2+16(%q0), %%xmm14 # sb2t \n\t" \
                  : "=c" (const_ptr) \
                  : \
                  : "memory" )

#define vpaes_ssse3_prepare_dec(const_ptr) \
    vpaes_ssse3_prepare(); \
    asm volatile ("lea	.Laes_consts(%%rip), %q0 \n\t" \
                  "movdqa	          (%q0), %%xmm9  # 0F \n\t" \
                  "movdqa	.Lk_inv   (%q0), %%xmm10 # inv \n\t" \
                  "movdqa	.Lk_inv+16(%q0), %%xmm11 # inva \n\t" \
                  "movdqa	.Lk_dsb9   (%q0), %%xmm13 # sb9u \n\t" \
                  "movdqa	.Lk_dsb9+16(%q0), %%xmm12 # sb9t \n\t" \
                  "movdqa	.Lk_dsbd   (%q0), %%xmm15 # sbdu \n\t" \
                  "movdqa	.Lk_dsbb   (%q0), %%xmm14 # sbbu \n\t" \
                  "movdqa	.Lk_dsbe   (%q0), %%xmm8 # sbeu \n\t" \
                  : "=c" (const_ptr) \
                  : \
                  : "memory" )



void
_gcry_aes_ssse3_do_setkey (RIJNDAEL_context *ctx, const byte *key)
{
  unsigned int keybits = (ctx->rounds - 10) * 32 + 128;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare();

  asm volatile ("leaq %q[key], %%rdi"			"\n\t"
                "movl %[bits], %%esi"			"\n\t"
                "leaq %[buf], %%rdx"			"\n\t"
                "movl %[dir], %%ecx"			"\n\t"
                "movl %[rotoffs], %%r8d"		"\n\t"
                "call _aes_schedule_core"		"\n\t"
                :
                : [key] "m" (*key),
                  [bits] "g" (keybits),
                  [buf] "m" (ctx->keyschenc32[0][0]),
                  [dir] "g" (0),
                  [rotoffs] "g" (48)
                : "r8", "r9", "r10", "r11", "rax", "rcx", "rdx", "rdi", "rsi",
                  "cc", "memory");

  vpaes_ssse3_cleanup();

  /* Save key for setting up decryption. */
  memcpy(&ctx->keyschdec32[0][0], key, keybits / 8);
}


/* Make a decryption key from an encryption key. */
void
_gcry_aes_ssse3_prepare_decryption (RIJNDAEL_context *ctx)
{
  unsigned int keybits = (ctx->rounds - 10) * 32 + 128;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare();

  asm volatile ("leaq %q[key], %%rdi"			"\n\t"
                "movl %[bits], %%esi"			"\n\t"
                "leaq %[buf], %%rdx"			"\n\t"
                "movl %[dir], %%ecx"			"\n\t"
                "movl %[rotoffs], %%r8d"		"\n\t"
                "call _aes_schedule_core"		"\n\t"
                :
                : [key] "m" (ctx->keyschdec32[0][0]),
                  [bits] "g" (keybits),
                  [buf] "m" (ctx->keyschdec32[ctx->rounds][0]),
                  [dir] "g" (1),
                  [rotoffs] "g" ((keybits == 192) ? 0 : 32)
                : "r8", "r9", "r10", "r11", "rax", "rcx", "rdx", "rdi", "rsi",
                  "cc", "memory");

  vpaes_ssse3_cleanup();
}


/* Encrypt one block using the Intel SSSE3 instructions.  Block is input
* and output through SSE register xmm0. */
static inline void
do_vpaes_ssse3_enc (const RIJNDAEL_context *ctx, unsigned int nrounds,
                    const void *aes_const_ptr)
{
  unsigned int middle_rounds = nrounds - 1;
  const void *keysched = ctx->keyschenc32;

  asm volatile ("call _aes_encrypt_core"		"\n\t"
                : "+a" (middle_rounds), "+d" (keysched)
                : "c" (aes_const_ptr)
                : "rdi", "rsi", "cc", "memory");
}


/* Decrypt one block using the Intel SSSE3 instructions.  Block is input
* and output through SSE register xmm0. */
static inline void
do_vpaes_ssse3_dec (const RIJNDAEL_context *ctx, unsigned int nrounds,
                    const void *aes_const_ptr)
{
  unsigned int middle_rounds = nrounds - 1;
  const void *keysched = ctx->keyschdec32;

  asm volatile ("call _aes_decrypt_core"		"\n\t"
                : "+a" (middle_rounds), "+d" (keysched)
                : "c" (aes_const_ptr)
                : "rsi", "cc", "memory");
}


unsigned int
_gcry_aes_ssse3_encrypt (const RIJNDAEL_context *ctx, unsigned char *dst,
                        const unsigned char *src)
{
  unsigned int nrounds = ctx->rounds;
  const void *aes_const_ptr;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc (aes_const_ptr);
  asm volatile ("movdqu %[src], %%xmm0\n\t"
                :
                : [src] "m" (*src)
                : "memory" );
  do_vpaes_ssse3_enc (ctx, nrounds, aes_const_ptr);
  asm volatile ("movdqu %%xmm0, %[dst]\n\t"
                : [dst] "=m" (*dst)
                :
                : "memory" );
  vpaes_ssse3_cleanup ();
  return 0;
}


void
_gcry_aes_ssse3_cfb_enc (RIJNDAEL_context *ctx, unsigned char *outbuf,
                        const unsigned char *inbuf, unsigned char *iv,
                        size_t nblocks)
{
  unsigned int nrounds = ctx->rounds;
  const void *aes_const_ptr;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc (aes_const_ptr);

  asm volatile ("movdqu %[iv], %%xmm0\n\t"
                : /* No output */
                : [iv] "m" (*iv)
                : "memory" );

  for ( ;nblocks; nblocks-- )
    {
      do_vpaes_ssse3_enc (ctx, nrounds, aes_const_ptr);

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

  vpaes_ssse3_cleanup ();
}


void
_gcry_aes_ssse3_cbc_enc (RIJNDAEL_context *ctx, unsigned char *outbuf,
                        const unsigned char *inbuf, unsigned char *iv,
                        size_t nblocks, int cbc_mac)
{
  unsigned int nrounds = ctx->rounds;
  const void *aes_const_ptr;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc (aes_const_ptr);

  asm volatile ("movdqu %[iv], %%xmm7\n\t"
                : /* No output */
                : [iv] "m" (*iv)
                : "memory" );

  for ( ;nblocks; nblocks-- )
    {
      asm volatile ("movdqu %[inbuf], %%xmm0\n\t"
                    "pxor %%xmm7, %%xmm0\n\t"
                    : /* No output */
                    : [inbuf] "m" (*inbuf)
                    : "memory" );

      do_vpaes_ssse3_enc (ctx, nrounds, aes_const_ptr);

      asm volatile ("movdqa %%xmm0, %%xmm7\n\t"
                    "movdqu %%xmm0, %[outbuf]\n\t"
                    : [outbuf] "=m" (*outbuf)
                    :
                    : "memory" );

      inbuf += BLOCKSIZE;
      if (!cbc_mac)
        outbuf += BLOCKSIZE;
    }

  asm volatile ("movdqu %%xmm7, %[iv]\n\t"
                : [iv] "=m" (*iv)
                :
                : "memory" );

  vpaes_ssse3_cleanup ();
}


void
_gcry_aes_ssse3_ctr_enc (RIJNDAEL_context *ctx, unsigned char *outbuf,
                        const unsigned char *inbuf, unsigned char *ctr,
                        size_t nblocks)
{
  static const unsigned char be_mask[16] __attribute__ ((aligned (16))) =
    { 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
  unsigned int nrounds = ctx->rounds;
  const void *aes_const_ptr;
  byte ssse3_state[SSSE3_STATE_SIZE];
  u64 ctrlow;

  vpaes_ssse3_prepare_enc (aes_const_ptr);

  asm volatile ("movdqa %[mask], %%xmm6\n\t" /* Preload mask */
                "movdqa (%[ctr]), %%xmm7\n\t"  /* Preload CTR */
                "movq 8(%[ctr]), %q[ctrlow]\n\t"
                "bswapq %q[ctrlow]\n\t"
                : [ctrlow] "=r" (ctrlow)
                : [mask] "m" (*be_mask),
                  [ctr] "r" (ctr)
                : "memory", "cc");

  for ( ;nblocks; nblocks-- )
    {
      asm volatile ("movdqa %%xmm7, %%xmm0\n\t"     /* xmm0 := CTR (xmm7)  */
                    "pcmpeqd %%xmm1, %%xmm1\n\t"
                    "psrldq $8, %%xmm1\n\t"         /* xmm1 = -1 */

                    "pshufb %%xmm6, %%xmm7\n\t"
                    "psubq  %%xmm1, %%xmm7\n\t"     /* xmm7++ (big endian) */

                    /* detect if 64-bit carry handling is needed */
                    "incq   %q[ctrlow]\n\t"
                    "jnz    .Lno_carry%=\n\t"

                    "pslldq $8, %%xmm1\n\t"         /* move lower 64-bit to high */
                    "psubq   %%xmm1, %%xmm7\n\t"    /* add carry to upper 64bits */

                    ".Lno_carry%=:\n\t"

                    "pshufb %%xmm6, %%xmm7\n\t"
                    :
                    : [ctr] "r" (ctr), [ctrlow] "r" (ctrlow)
                    : "cc", "memory");

      do_vpaes_ssse3_enc (ctx, nrounds, aes_const_ptr);

      asm volatile ("movdqu %[src], %%xmm1\n\t"      /* xmm1 := input   */
                    "pxor %%xmm1, %%xmm0\n\t"        /* EncCTR ^= input  */
                    "movdqu %%xmm0, %[dst]"          /* Store EncCTR.    */
                    : [dst] "=m" (*outbuf)
                    : [src] "m" (*inbuf)
                    : "memory");

      outbuf += BLOCKSIZE;
      inbuf  += BLOCKSIZE;
    }

  asm volatile ("movdqu %%xmm7, %[ctr]\n\t"   /* Update CTR (mem).       */
                : [ctr] "=m" (*ctr)
                :
                : "memory" );

  vpaes_ssse3_cleanup ();
}


unsigned int
_gcry_aes_ssse3_decrypt (const RIJNDAEL_context *ctx, unsigned char *dst,
                        const unsigned char *src)
{
  unsigned int nrounds = ctx->rounds;
  const void *aes_const_ptr;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_dec (aes_const_ptr);
  asm volatile ("movdqu %[src], %%xmm0\n\t"
                :
                : [src] "m" (*src)
                : "memory" );
  do_vpaes_ssse3_dec (ctx, nrounds, aes_const_ptr);
  asm volatile ("movdqu %%xmm0, %[dst]\n\t"
                : [dst] "=m" (*dst)
                :
                : "memory" );
  vpaes_ssse3_cleanup ();
  return 0;
}


void
_gcry_aes_ssse3_cfb_dec (RIJNDAEL_context *ctx, unsigned char *outbuf,
                        const unsigned char *inbuf, unsigned char *iv,
                        size_t nblocks)
{
  unsigned int nrounds = ctx->rounds;
  const void *aes_const_ptr;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc (aes_const_ptr);

  asm volatile ("movdqu %[iv], %%xmm0\n\t"
                : /* No output */
                : [iv] "m" (*iv)
                : "memory" );

  for ( ;nblocks; nblocks-- )
    {
      do_vpaes_ssse3_enc (ctx, nrounds, aes_const_ptr);

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

  vpaes_ssse3_cleanup ();
}


void
_gcry_aes_ssse3_cbc_dec (RIJNDAEL_context *ctx, unsigned char *outbuf,
                        const unsigned char *inbuf, unsigned char *iv,
                        size_t nblocks)
{
  unsigned int nrounds = ctx->rounds;
  const void *aes_const_ptr;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_dec (aes_const_ptr);

  asm volatile
    ("movdqu %[iv], %%xmm7\n\t"	/* use xmm7 as fast IV storage */
    : /* No output */
    : [iv] "m" (*iv)
    : "memory");

  for ( ;nblocks; nblocks-- )
    {
      asm volatile
        ("movdqu %[inbuf], %%xmm0\n\t"
        "movdqa %%xmm0, %%xmm6\n\t"    /* use xmm6 as savebuf */
        : /* No output */
        : [inbuf] "m" (*inbuf)
        : "memory");

      do_vpaes_ssse3_dec (ctx, nrounds, aes_const_ptr);

      asm volatile
        ("pxor %%xmm7, %%xmm0\n\t"	/* xor IV with output */
        "movdqu %%xmm0, %[outbuf]\n\t"
        "movdqu %%xmm6, %%xmm7\n\t"	/* store savebuf as new IV */
        : [outbuf] "=m" (*outbuf)
        :
        : "memory");

      outbuf += BLOCKSIZE;
      inbuf  += BLOCKSIZE;
    }

  asm volatile
    ("movdqu %%xmm7, %[iv]\n\t"	/* store IV */
    : /* No output */
    : [iv] "m" (*iv)
    : "memory");

  vpaes_ssse3_cleanup ();
}


static inline const unsigned char *
get_l (gcry_cipher_hd_t c, unsigned char *l_tmp, u64 i, unsigned char *iv,
       unsigned char *ctr, const void **aes_const_ptr,
       byte ssse3_state[SSSE3_STATE_SIZE], int encrypt)
{
  const unsigned char *l;
  unsigned int ntz;

  if (i & 1)
    return c->u_mode.ocb.L[0];
  else if (i & 2)
    return c->u_mode.ocb.L[1];
  else if (i & 0xffffffffU)
    {
      asm ("rep;bsf %k[low], %k[ntz]\n\t"
           : [ntz] "=r" (ntz)
           : [low] "r" (i & 0xffffffffU)
           : "cc");
    }
  else
    {
      if (OCB_L_TABLE_SIZE < 32)
        {
          ntz = 32;
        }
      else if (i)
        {
          asm ("rep;bsf %k[high], %k[ntz]\n\t"
               : [ntz] "=r" (ntz)
               : [high] "r" (i >> 32)
               : "cc");
          ntz += 32;
        }
      else
        {
          ntz = 64;
        }
    }

  if (ntz < OCB_L_TABLE_SIZE)
    {
      l = c->u_mode.ocb.L[ntz];
    }
  else
    {
      /* Store Offset & Checksum before calling external function */
      asm volatile ("movdqu %%xmm7, %[iv]\n\t"
                    "movdqu %%xmm6, %[ctr]\n\t"
                    : [iv] "=m" (*iv),
                      [ctr] "=m" (*ctr)
                    :
                    : "memory" );

      /* Restore SSSE3 state. */
      vpaes_ssse3_cleanup();

      l = _gcry_cipher_ocb_get_l (c, l_tmp, i);

      /* Save SSSE3 state. */
      if (encrypt)
	{
	  vpaes_ssse3_prepare_enc (*aes_const_ptr);
	}
      else
	{
	  vpaes_ssse3_prepare_dec (*aes_const_ptr);
	}

      /* Restore Offset & Checksum */
      asm volatile ("movdqu %[iv], %%xmm7\n\t"
                    "movdqu %[ctr], %%xmm6\n\t"
                    : /* No output */
                    : [iv] "m" (*iv),
                      [ctr] "m" (*ctr)
                    : "memory" );
    }

  return l;
}


static void
ssse3_ocb_enc (gcry_cipher_hd_t c, void *outbuf_arg,
               const void *inbuf_arg, size_t nblocks)
{
  union { unsigned char x1[16] ATTR_ALIGNED_16; u32 x32[4]; } l_tmp;
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  u64 n = c->u_mode.ocb.data_nblocks;
  unsigned int nrounds = ctx->rounds;
  const void *aes_const_ptr;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc (aes_const_ptr);

  /* Preload Offset and Checksum */
  asm volatile ("movdqu %[iv], %%xmm7\n\t"
                "movdqu %[ctr], %%xmm6\n\t"
                : /* No output */
                : [iv] "m" (*c->u_iv.iv),
                  [ctr] "m" (*c->u_ctr.ctr)
                : "memory" );

  for ( ;nblocks; nblocks-- )
    {
      const unsigned char *l;

      l = get_l(c, l_tmp.x1, ++n, c->u_iv.iv, c->u_ctr.ctr, &aes_const_ptr,
		ssse3_state, 1);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* Checksum_i = Checksum_{i-1} xor P_i  */
      /* C_i = Offset_i xor ENCIPHER(K, P_i xor Offset_i)  */
      asm volatile ("movdqu %[l],     %%xmm1\n\t"
                    "movdqu %[inbuf], %%xmm0\n\t"
                    "pxor   %%xmm1,   %%xmm7\n\t"
                    "pxor   %%xmm0,   %%xmm6\n\t"
                    "pxor   %%xmm7,   %%xmm0\n\t"
                    :
                    : [l] "m" (*l),
                      [inbuf] "m" (*inbuf)
                    : "memory" );

      do_vpaes_ssse3_enc (ctx, nrounds, aes_const_ptr);

      asm volatile ("pxor   %%xmm7, %%xmm0\n\t"
                    "movdqu %%xmm0, %[outbuf]\n\t"
                    : [outbuf] "=m" (*outbuf)
                    :
                    : "memory" );

      inbuf += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  c->u_mode.ocb.data_nblocks = n;
  asm volatile ("movdqu %%xmm7, %[iv]\n\t"
                "movdqu %%xmm6, %[ctr]\n\t"
                : [iv] "=m" (*c->u_iv.iv),
                  [ctr] "=m" (*c->u_ctr.ctr)
                :
                : "memory" );

  wipememory(&l_tmp, sizeof(l_tmp));
  vpaes_ssse3_cleanup ();
}

static void
ssse3_ocb_dec (gcry_cipher_hd_t c, void *outbuf_arg,
               const void *inbuf_arg, size_t nblocks)
{
  union { unsigned char x1[16] ATTR_ALIGNED_16; u32 x32[4]; } l_tmp;
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  u64 n = c->u_mode.ocb.data_nblocks;
  unsigned int nrounds = ctx->rounds;
  const void *aes_const_ptr;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_dec (aes_const_ptr);

  /* Preload Offset and Checksum */
  asm volatile ("movdqu %[iv], %%xmm7\n\t"
                "movdqu %[ctr], %%xmm6\n\t"
                : /* No output */
                : [iv] "m" (*c->u_iv.iv),
                  [ctr] "m" (*c->u_ctr.ctr)
                : "memory" );

  for ( ;nblocks; nblocks-- )
    {
      const unsigned char *l;

      l = get_l(c, l_tmp.x1, ++n, c->u_iv.iv, c->u_ctr.ctr, &aes_const_ptr,
		ssse3_state, 0);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* P_i = Offset_i xor DECIPHER(K, C_i xor Offset_i)  */
      /* Checksum_i = Checksum_{i-1} xor P_i  */
      asm volatile ("movdqu %[l],     %%xmm1\n\t"
                    "movdqu %[inbuf], %%xmm0\n\t"
                    "pxor   %%xmm1,   %%xmm7\n\t"
                    "pxor   %%xmm7,   %%xmm0\n\t"
                    :
                    : [l] "m" (*l),
                      [inbuf] "m" (*inbuf)
                    : "memory" );

      do_vpaes_ssse3_dec (ctx, nrounds, aes_const_ptr);

      asm volatile ("pxor   %%xmm7, %%xmm0\n\t"
                    "pxor   %%xmm0, %%xmm6\n\t"
                    "movdqu %%xmm0, %[outbuf]\n\t"
                    : [outbuf] "=m" (*outbuf)
                    :
                    : "memory" );

      inbuf += BLOCKSIZE;
      outbuf += BLOCKSIZE;
    }

  c->u_mode.ocb.data_nblocks = n;
  asm volatile ("movdqu %%xmm7, %[iv]\n\t"
                "movdqu %%xmm6, %[ctr]\n\t"
                : [iv] "=m" (*c->u_iv.iv),
                  [ctr] "=m" (*c->u_ctr.ctr)
                :
                : "memory" );

  wipememory(&l_tmp, sizeof(l_tmp));
  vpaes_ssse3_cleanup ();
}


void
_gcry_aes_ssse3_ocb_crypt(gcry_cipher_hd_t c, void *outbuf_arg,
                          const void *inbuf_arg, size_t nblocks, int encrypt)
{
  if (encrypt)
    ssse3_ocb_enc(c, outbuf_arg, inbuf_arg, nblocks);
  else
    ssse3_ocb_dec(c, outbuf_arg, inbuf_arg, nblocks);
}


void
_gcry_aes_ssse3_ocb_auth (gcry_cipher_hd_t c, const void *abuf_arg,
                          size_t nblocks)
{
  union { unsigned char x1[16] ATTR_ALIGNED_16; u32 x32[4]; } l_tmp;
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  const unsigned char *abuf = abuf_arg;
  u64 n = c->u_mode.ocb.aad_nblocks;
  unsigned int nrounds = ctx->rounds;
  const void *aes_const_ptr;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc (aes_const_ptr);

  /* Preload Offset and Sum */
  asm volatile ("movdqu %[iv], %%xmm7\n\t"
                "movdqu %[ctr], %%xmm6\n\t"
                : /* No output */
                : [iv] "m" (*c->u_mode.ocb.aad_offset),
                  [ctr] "m" (*c->u_mode.ocb.aad_sum)
                : "memory" );

  for ( ;nblocks; nblocks-- )
    {
      const unsigned char *l;

      l = get_l(c, l_tmp.x1, ++n, c->u_mode.ocb.aad_offset,
                c->u_mode.ocb.aad_sum, &aes_const_ptr, ssse3_state, 1);

      /* Offset_i = Offset_{i-1} xor L_{ntz(i)} */
      /* Sum_i = Sum_{i-1} xor ENCIPHER(K, A_i xor Offset_i)  */
      asm volatile ("movdqu %[l],     %%xmm1\n\t"
                    "movdqu %[abuf],  %%xmm0\n\t"
                    "pxor   %%xmm1,   %%xmm7\n\t"
                    "pxor   %%xmm7,   %%xmm0\n\t"
                    :
                    : [l] "m" (*l),
                      [abuf] "m" (*abuf)
                    : "memory" );

      do_vpaes_ssse3_enc (ctx, nrounds, aes_const_ptr);

      asm volatile ("pxor   %%xmm0,   %%xmm6\n\t"
                    :
                    :
                    : "memory" );

      abuf += BLOCKSIZE;
    }

  c->u_mode.ocb.aad_nblocks = n;
  asm volatile ("movdqu %%xmm7, %[iv]\n\t"
                "movdqu %%xmm6, %[ctr]\n\t"
                : [iv] "=m" (*c->u_mode.ocb.aad_offset),
                  [ctr] "=m" (*c->u_mode.ocb.aad_sum)
                :
                : "memory" );

  wipememory(&l_tmp, sizeof(l_tmp));
  vpaes_ssse3_cleanup ();
}


#ifdef HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS
# define X(...)
#else
# define X(...) __VA_ARGS__
#endif

asm (
  "\n\t" "##"
  "\n\t" "## Constant-time SSSE3 AES core implementation."
  "\n\t" "##"
  "\n\t" "## By Mike Hamburg (Stanford University), 2009"
  "\n\t" "## Public domain."
  "\n\t" "##"

  "\n\t" ".text"

  "\n\t" "##"
  "\n\t" "##  _aes_encrypt_core"
  "\n\t" "##"
  "\n\t" "##  AES-encrypt %xmm0."
  "\n\t" "##"
  "\n\t" "##  Inputs:"
  "\n\t" "##     %xmm0 = input"
  "\n\t" "##     %xmm9-%xmm15 as in .Laes_preheat"
  "\n\t" "##     %rcx  = .Laes_consts"
  "\n\t" "##    (%rdx) = scheduled keys"
  "\n\t" "##     %rax  = nrounds - 1"
  "\n\t" "##"
  "\n\t" "##  Output in %xmm0"
  "\n\t" "##  Clobbers  %xmm1-%xmm4, %r9, %r11, %rax"
  "\n\t" "##  Preserves %xmm6 - %xmm7 so you get some local vectors"
  "\n\t" "##"
  "\n\t" "##"
  "\n\t" ".align 16"
X("\n\t" ".type _aes_encrypt_core,@function")
  "\n\t" "_aes_encrypt_core:"
  "\n\t" "	leaq	.Lk_mc_backward(%rcx), %rdi"
  "\n\t" "	mov	$16,	%rsi"
  "\n\t" "	movdqa	.Lk_ipt   (%rcx), %xmm2 # iptlo"
  "\n\t" "	movdqa	%xmm9,	%xmm1"
  "\n\t" "	pandn	%xmm0,	%xmm1"
  "\n\t" "	psrld	$4,	%xmm1"
  "\n\t" "	pand	%xmm9,	%xmm0"
  "\n\t" "	pshufb	%xmm0,	%xmm2"
  "\n\t" "	movdqa	.Lk_ipt+16(%rcx), %xmm0 # ipthi"
  "\n\t" "	pshufb	%xmm1,	%xmm0"
  "\n\t" "	pxor	(%rdx),%xmm2"
  "\n\t" "	pxor	%xmm2,	%xmm0"
  "\n\t" "	add	$16,	%rdx"
  "\n\t" "	jmp	.Laes_entry"

  "\n\t" ".align 8"
  "\n\t" ".Laes_loop:"
  "\n\t" "	# middle of middle round"
  "\n\t" "	movdqa  %xmm13,	%xmm4	# 4 : sb1u"
  "\n\t" "	pshufb  %xmm2,	%xmm4   # 4 = sb1u"
  "\n\t" "	pxor	(%rdx),	%xmm4	# 4 = sb1u + k"
  "\n\t" "	movdqa  %xmm12,	%xmm0	# 0 : sb1t"
  "\n\t" "	pshufb  %xmm3,	%xmm0	# 0 = sb1t"
  "\n\t" "	pxor	%xmm4,	%xmm0	# 0 = A"
  "\n\t" "	movdqa  %xmm15,	%xmm4	# 4 : sb2u"
  "\n\t" "	pshufb	%xmm2,	%xmm4	# 4 = sb2u"
  "\n\t" "	movdqa	.Lk_mc_forward-.Lk_mc_backward(%rsi,%rdi), %xmm1"
  "\n\t" "	movdqa	%xmm14, %xmm2	# 2 : sb2t"
  "\n\t" "	pshufb	%xmm3,  %xmm2	# 2 = sb2t"
  "\n\t" "	pxor	%xmm4,  %xmm2	# 2 = 2A"
  "\n\t" "	movdqa	%xmm0,  %xmm3	# 3 = A"
  "\n\t" "	pshufb  %xmm1,  %xmm0	# 0 = B"
  "\n\t" "	pxor	%xmm2,  %xmm0	# 0 = 2A+B"
  "\n\t" "	pshufb	(%rsi,%rdi), %xmm3  # 3 = D"
  "\n\t" "	lea	16(%esi),%esi	# next mc"
  "\n\t" "	pxor	%xmm0,	%xmm3	# 3 = 2A+B+D"
  "\n\t" "	lea	16(%rdx),%rdx	# next key"
  "\n\t" "	pshufb  %xmm1,	%xmm0	# 0 = 2B+C"
  "\n\t" "	pxor	%xmm3,	%xmm0	# 0 = 2A+3B+C+D"
  "\n\t" "	and	$48, %rsi	# ... mod 4"
  "\n\t" "	dec	%rax		# nr--"

  "\n\t" ".Laes_entry:"
  "\n\t" "	# top of round"
  "\n\t" "	movdqa  %xmm9, 	%xmm1	# 1 : i"
  "\n\t" "	pandn	%xmm0, 	%xmm1	# 1 = i<<4"
  "\n\t" "	psrld	$4,    	%xmm1   # 1 = i"
  "\n\t" "	pand	%xmm9, 	%xmm0   # 0 = k"
  "\n\t" "	movdqa	%xmm11, %xmm2	# 2 : a/k"
  "\n\t" "	pshufb  %xmm0,  %xmm2	# 2 = a/k"
  "\n\t" "	pxor	%xmm1,	%xmm0	# 0 = j"
  "\n\t" "	movdqa  %xmm10,	%xmm3  	# 3 : 1/i"
  "\n\t" "	pshufb  %xmm1, 	%xmm3  	# 3 = 1/i"
  "\n\t" "	pxor	%xmm2, 	%xmm3  	# 3 = iak = 1/i + a/k"
  "\n\t" "	movdqa	%xmm10,	%xmm4  	# 4 : 1/j"
  "\n\t" "	pshufb	%xmm0, 	%xmm4  	# 4 = 1/j"
  "\n\t" "	pxor	%xmm2, 	%xmm4  	# 4 = jak = 1/j + a/k"
  "\n\t" "	movdqa  %xmm10,	%xmm2  	# 2 : 1/iak"
  "\n\t" "	pshufb  %xmm3,	%xmm2  	# 2 = 1/iak"
  "\n\t" "	pxor	%xmm0, 	%xmm2  	# 2 = io"
  "\n\t" "	movdqa  %xmm10, %xmm3   # 3 : 1/jak"
  "\n\t" "	pshufb  %xmm4,  %xmm3   # 3 = 1/jak"
  "\n\t" "	pxor	%xmm1,  %xmm3   # 3 = jo"
  "\n\t" "	jnz	.Laes_loop"

  "\n\t" "	# middle of last round"
  "\n\t" "	movdqa	.Lk_sbo(%rcx), %xmm4	# 3 : sbou"
  "\n\t" "	pshufb  %xmm2,  %xmm4   # 4 = sbou"
  "\n\t" "	pxor	(%rdx), %xmm4   # 4 = sb1u + k"
  "\n\t" "	movdqa	.Lk_sbo+16(%rcx), %xmm0	# 0 : sbot"
  "\n\t" "	pshufb  %xmm3,	%xmm0	# 0 = sb1t"
  "\n\t" "	pxor	%xmm4,	%xmm0	# 0 = A"
  "\n\t" "	pshufb	.Lk_sr(%rsi,%rcx), %xmm0"
  "\n\t" "	ret"
X("\n\t" ".size _aes_encrypt_core,.-_aes_encrypt_core")

  "\n\t" "##"
  "\n\t" "##  Decryption core"
  "\n\t" "##"
  "\n\t" "##  Same API as encryption core."
  "\n\t" "##"
  "\n\t" ".align 16"
X("\n\t" ".type _aes_decrypt_core,@function")
  "\n\t" "_aes_decrypt_core:"
  "\n\t" "	movl	%eax,	%esi"
  "\n\t" "	shll	$4,	%esi"
  "\n\t" "	xorl	$48,	%esi"
  "\n\t" "	andl	$48,	%esi"
  "\n\t" "	movdqa	.Lk_dipt   (%rcx), %xmm2 # iptlo"
  "\n\t" "	movdqa	%xmm9,	%xmm1"
  "\n\t" "	pandn	%xmm0,	%xmm1"
  "\n\t" "	psrld	$4,	%xmm1"
  "\n\t" "	pand	%xmm9,	%xmm0"
  "\n\t" "	pshufb	%xmm0,	%xmm2"
  "\n\t" "	movdqa	.Lk_dipt+16(%rcx), %xmm0 # ipthi"
  "\n\t" "	pshufb	%xmm1,	%xmm0"
  "\n\t" "	pxor	(%rdx),	%xmm2"
  "\n\t" "	pxor	%xmm2,	%xmm0"
  "\n\t" "	movdqa	.Lk_mc_forward+48(%rcx), %xmm5"
  "\n\t" "	lea	16(%rdx), %rdx"
  "\n\t" "	neg	%rax"
  "\n\t" "	jmp	.Laes_dec_entry"

  "\n\t" ".align 16"
  "\n\t" ".Laes_dec_loop:"
  "\n\t" "##"
  "\n\t" "##  Inverse mix columns"
  "\n\t" "##"
  "\n\t" "	movdqa  %xmm13,	%xmm4		# 4 : sb9u"
  "\n\t" "	pshufb	%xmm2,	%xmm4		# 4 = sb9u"
  "\n\t" "	pxor	(%rdx),	%xmm4"
  "\n\t" "	movdqa  %xmm12,	%xmm0		# 0 : sb9t"
  "\n\t" "	pshufb	%xmm3,	%xmm0		# 0 = sb9t"
  "\n\t" "	movdqa  .Lk_dsbd+16(%rcx),%xmm1	# 1 : sbdt"
  "\n\t" "	pxor	%xmm4,	%xmm0		# 0 = ch"
  "\n\t" "	lea	16(%rdx), %rdx		# next round key"

  "\n\t" "	pshufb	%xmm5,	%xmm0		# MC ch"
  "\n\t" "	movdqa  %xmm15,	%xmm4		# 4 : sbdu"
  "\n\t" "	pshufb	%xmm2,	%xmm4		# 4 = sbdu"
  "\n\t" "	pxor	%xmm0,	%xmm4		# 4 = ch"
  "\n\t" "	pshufb	%xmm3,	%xmm1		# 1 = sbdt"
  "\n\t" "	pxor	%xmm4,	%xmm1		# 1 = ch"

  "\n\t" "	pshufb	%xmm5,	%xmm1		# MC ch"
  "\n\t" "	movdqa  %xmm14,	%xmm4		# 4 : sbbu"
  "\n\t" "	pshufb	%xmm2,	%xmm4		# 4 = sbbu"
  "\n\t" "      inc     %rax                    # nr--"
  "\n\t" "	pxor	%xmm1,	%xmm4		# 4 = ch"
  "\n\t" "	movdqa  .Lk_dsbb+16(%rcx),%xmm0	# 0 : sbbt"
  "\n\t" "	pshufb	%xmm3,	%xmm0		# 0 = sbbt"
  "\n\t" "	pxor	%xmm4,	%xmm0		# 0 = ch"

  "\n\t" "	pshufb	%xmm5,	%xmm0		# MC ch"
  "\n\t" "	movdqa  %xmm8,	%xmm4		# 4 : sbeu"
  "\n\t" "	pshufb	%xmm2,	%xmm4		# 4 = sbeu"
  "\n\t" "	pshufd	$0x93,	%xmm5,	%xmm5"
  "\n\t" "	pxor	%xmm0,	%xmm4		# 4 = ch"
  "\n\t" "	movdqa  .Lk_dsbe+16(%rcx),%xmm0	# 0 : sbet"
  "\n\t" "	pshufb	%xmm3,	%xmm0		# 0 = sbet"
  "\n\t" "	pxor	%xmm4,	%xmm0		# 0 = ch"

  "\n\t" ".Laes_dec_entry:"
  "\n\t" "	# top of round"
  "\n\t" "	movdqa  %xmm9, 	%xmm1	# 1 : i"
  "\n\t" "	pandn	%xmm0, 	%xmm1	# 1 = i<<4"
  "\n\t" "	psrld	$4,    	%xmm1   # 1 = i"
  "\n\t" "	pand	%xmm9, 	%xmm0   # 0 = k"
  "\n\t" "	movdqa	%xmm11, %xmm2	# 2 : a/k"
  "\n\t" "	pshufb  %xmm0,  %xmm2	# 2 = a/k"
  "\n\t" "	pxor	%xmm1,	%xmm0	# 0 = j"
  "\n\t" "	movdqa  %xmm10,	%xmm3  	# 3 : 1/i"
  "\n\t" "	pshufb  %xmm1, 	%xmm3  	# 3 = 1/i"
  "\n\t" "	pxor	%xmm2, 	%xmm3  	# 3 = iak = 1/i + a/k"
  "\n\t" "	movdqa	%xmm10,	%xmm4  	# 4 : 1/j"
  "\n\t" "	pshufb	%xmm0, 	%xmm4  	# 4 = 1/j"
  "\n\t" "	pxor	%xmm2, 	%xmm4  	# 4 = jak = 1/j + a/k"
  "\n\t" "	movdqa  %xmm10,	%xmm2  	# 2 : 1/iak"
  "\n\t" "	pshufb  %xmm3,	%xmm2  	# 2 = 1/iak"
  "\n\t" "	pxor	%xmm0, 	%xmm2  	# 2 = io"
  "\n\t" "	movdqa  %xmm10, %xmm3   # 3 : 1/jak"
  "\n\t" "	pshufb  %xmm4,  %xmm3   # 3 = 1/jak"
  "\n\t" "	pxor	%xmm1,  %xmm3   # 3 = jo"
  "\n\t" "	jnz	.Laes_dec_loop"

  "\n\t" "	# middle of last round"
  "\n\t" "	movdqa	.Lk_dsbo(%rcx), %xmm4		# 3 : sbou"
  "\n\t" "	pshufb  %xmm2,  %xmm4   # 4 = sbou"
  "\n\t" "	pxor	(%rdx), %xmm4   # 4 = sb1u + k"
  "\n\t" "	movdqa	.Lk_dsbo+16(%rcx), %xmm0	# 0 : sbot"
  "\n\t" "	pshufb  %xmm3,	%xmm0	# 0 = sb1t"
  "\n\t" "	pxor	%xmm4,	%xmm0	# 0 = A"
  "\n\t" "	pshufb	.Lk_sr(%rsi,%rcx), %xmm0"
  "\n\t" "	ret"
X("\n\t" ".size _aes_decrypt_core,.-_aes_decrypt_core")

  "\n\t" "########################################################"
  "\n\t" "##                                                    ##"
  "\n\t" "##                  AES key schedule                  ##"
  "\n\t" "##                                                    ##"
  "\n\t" "########################################################"

  "\n\t" ".align 16"
X("\n\t" ".type _aes_schedule_core,@function")
  "\n\t" "_aes_schedule_core:"
  "\n\t" "	# rdi = key"
  "\n\t" "	# rsi = size in bits"
  "\n\t" "	# rdx = buffer"
  "\n\t" "	# rcx = direction.  0=encrypt, 1=decrypt"

  "\n\t" "	# load the tables"
  "\n\t" "	lea	.Laes_consts(%rip), %r10"
  "\n\t" "	movdqa	          (%r10), %xmm9  # 0F"
  "\n\t" "	movdqa	.Lk_inv   (%r10), %xmm10 # inv"
  "\n\t" "	movdqa	.Lk_inv+16(%r10), %xmm11 # inva"
  "\n\t" "	movdqa	.Lk_sb1   (%r10), %xmm13 # sb1u"
  "\n\t" "	movdqa	.Lk_sb1+16(%r10), %xmm12 # sb1t"
  "\n\t" "	movdqa	.Lk_sb2   (%r10), %xmm15 # sb2u"
  "\n\t" "	movdqa	.Lk_sb2+16(%r10), %xmm14 # sb2t"

  "\n\t" "	movdqa	.Lk_rcon(%r10), %xmm8	# load rcon"
  "\n\t" "	movdqu	(%rdi),	%xmm0		# load key (unaligned)"

  "\n\t" "	# input transform"
  "\n\t" "	movdqu	%xmm0,	%xmm3"
  "\n\t" "	lea	.Lk_ipt(%r10), %r11"
  "\n\t" "	call	.Laes_schedule_transform"
  "\n\t" "	movdqu	%xmm0,	%xmm7"

  "\n\t" "	test	%rcx,	%rcx"
  "\n\t" "	jnz	.Laes_schedule_am_decrypting"

  "\n\t" "	# encrypting, output zeroth round key after transform"
  "\n\t" "	movdqa	%xmm0,	(%rdx)"
  "\n\t" "	jmp	.Laes_schedule_go"

  "\n\t" ".Laes_schedule_am_decrypting:"
  "\n\t" "	# decrypting, output zeroth round key after shiftrows"
  "\n\t" "	pshufb  .Lk_sr(%r8,%r10),%xmm3"
  "\n\t" "	movdqa	%xmm3,	(%rdx)"
  "\n\t" "	xor	$48, 	%r8"

  "\n\t" ".Laes_schedule_go:"
  "\n\t" "	cmp	$192,	%rsi"
  "\n\t" "	je	.Laes_schedule_192"
  "\n\t" "	cmp	$256,	%rsi"
  "\n\t" "	je	.Laes_schedule_256"
  "\n\t" "	# 128: fall though"

  "\n\t" "##"
  "\n\t" "##  .Laes_schedule_128"
  "\n\t" "##"
  "\n\t" "##  128-bit specific part of key schedule."
  "\n\t" "##"
  "\n\t" "##  This schedule is really simple, because all its parts"
  "\n\t" "##  are accomplished by the subroutines."
  "\n\t" "##"
  "\n\t" ".Laes_schedule_128:"
  "\n\t" "	mov	$10, %rsi"

  "\n\t" ".Laes_schedule_128_L:"
  "\n\t" "	call 	.Laes_schedule_round"
  "\n\t" "	dec	%rsi"
  "\n\t" "	jz 	.Laes_schedule_mangle_last"
  "\n\t" "	call	.Laes_schedule_mangle	# write output"
  "\n\t" "	jmp 	.Laes_schedule_128_L"

  "\n\t" "##"
  "\n\t" "##  .Laes_schedule_192"
  "\n\t" "##"
  "\n\t" "##  192-bit specific part of key schedule."
  "\n\t" "##"
  "\n\t" "##  The main body of this schedule is the same as the 128-bit"
  "\n\t" "##  schedule, but with more smearing.  The long, high side is"
  "\n\t" "##  stored in %xmm7 as before, and the short, low side is in"
  "\n\t" "##  the high bits of %xmm6."
  "\n\t" "##"
  "\n\t" "##  This schedule is somewhat nastier, however, because each"
  "\n\t" "##  round produces 192 bits of key material, or 1.5 round keys."
  "\n\t" "##  Therefore, on each cycle we do 2 rounds and produce 3 round"
  "\n\t" "##  keys."
  "\n\t" "##"
  "\n\t" ".Laes_schedule_192:"
  "\n\t" "	movdqu	8(%rdi),%xmm0		# load key part 2 (very unaligned)"
  "\n\t" "	call	.Laes_schedule_transform	# input transform"
  "\n\t" "	pshufd	$0x0E,	%xmm0,	%xmm6"
  "\n\t" "	pslldq	$8,	%xmm6		# clobber low side with zeros"
  "\n\t" "	mov	$4,	%rsi"

  "\n\t" ".Laes_schedule_192_L:"
  "\n\t" "	call	.Laes_schedule_round"
  "\n\t" "	palignr	$8,%xmm6,%xmm0	"
  "\n\t" "	call	.Laes_schedule_mangle	# save key n"
  "\n\t" "	call	.Laes_schedule_192_smear"
  "\n\t" "	call	.Laes_schedule_mangle	# save key n+1"
  "\n\t" "	call	.Laes_schedule_round"
  "\n\t" "	dec	%rsi"
  "\n\t" "	jz 	.Laes_schedule_mangle_last"
  "\n\t" "	call	.Laes_schedule_mangle	# save key n+2"
  "\n\t" "	call	.Laes_schedule_192_smear"
  "\n\t" "	jmp	.Laes_schedule_192_L"

  "\n\t" "##"
  "\n\t" "##  .Laes_schedule_192_smear"
  "\n\t" "##"
  "\n\t" "##  Smear the short, low side in the 192-bit key schedule."
  "\n\t" "##"
  "\n\t" "##  Inputs:"
  "\n\t" "##    %xmm7: high side, b  a  x  y"
  "\n\t" "##    %xmm6:  low side, d  c  0  0"
  "\n\t" "##    %xmm13: 0"
  "\n\t" "##"
  "\n\t" "##  Outputs:"
  "\n\t" "##    %xmm6: b+c+d  b+c  0  0"
  "\n\t" "##    %xmm0: b+c+d  b+c  b  a"
  "\n\t" "##"
  "\n\t" ".Laes_schedule_192_smear:"
  "\n\t" "	pshufd	$0x80,	%xmm6,	%xmm0	# d c 0 0 -> c 0 0 0"
  "\n\t" "	pxor	%xmm0,	%xmm6		# -> c+d c 0 0"
  "\n\t" "	pshufd	$0xFE,	%xmm7,	%xmm0	# b a _ _ -> b b b a"
  "\n\t" "	pxor	%xmm6,	%xmm0		# -> b+c+d b+c b a"
  "\n\t" "	pshufd	$0x0E,	%xmm0,	%xmm6"
  "\n\t" "	pslldq	$8,	%xmm6		# clobber low side with zeros"
  "\n\t" "	ret"

  "\n\t" "##"
  "\n\t" "##  .Laes_schedule_256"
  "\n\t" "##"
  "\n\t" "##  256-bit specific part of key schedule."
  "\n\t" "##"
  "\n\t" "##  The structure here is very similar to the 128-bit"
  "\n\t" "##  schedule, but with an additional 'low side' in"
  "\n\t" "##  %xmm6.  The low side's rounds are the same as the"
  "\n\t" "##  high side's, except no rcon and no rotation."
  "\n\t" "##"
  "\n\t" ".Laes_schedule_256:"
  "\n\t" "	movdqu	16(%rdi),%xmm0		# load key part 2 (unaligned)"
  "\n\t" "	call	.Laes_schedule_transform	# input transform"
  "\n\t" "	mov	$7, %rsi"

  "\n\t" ".Laes_schedule_256_L:"
  "\n\t" "	call	.Laes_schedule_mangle	# output low result"
  "\n\t" "	movdqa	%xmm0,	%xmm6		# save cur_lo in xmm6"

  "\n\t" "	# high round"
  "\n\t" "	call	.Laes_schedule_round"
  "\n\t" "	dec	%rsi"
  "\n\t" "	jz 	.Laes_schedule_mangle_last"
  "\n\t" "	call	.Laes_schedule_mangle	"

  "\n\t" "	# low round. swap xmm7 and xmm6"
  "\n\t" "	pshufd	$0xFF,	%xmm0,	%xmm0"
  "\n\t" "	movdqa	%xmm7,	%xmm5"
  "\n\t" "	movdqa	%xmm6,	%xmm7"
  "\n\t" "	call	.Laes_schedule_low_round"
  "\n\t" "	movdqa	%xmm5,	%xmm7"

  "\n\t" "	jmp	.Laes_schedule_256_L"

  "\n\t" "##"
  "\n\t" "##  .Laes_schedule_round"
  "\n\t" "##"
  "\n\t" "##  Runs one main round of the key schedule on %xmm0, %xmm7"
  "\n\t" "##"
  "\n\t" "##  Specifically, runs subbytes on the high dword of %xmm0"
  "\n\t" "##  then rotates it by one byte and xors into the low dword of"
  "\n\t" "##  %xmm7."
  "\n\t" "##"
  "\n\t" "##  Adds rcon from low byte of %xmm8, then rotates %xmm8 for"
  "\n\t" "##  next rcon."
  "\n\t" "##"
  "\n\t" "##  Smears the dwords of %xmm7 by xoring the low into the"
  "\n\t" "##  second low, result into third, result into highest."
  "\n\t" "##"
  "\n\t" "##  Returns results in %xmm7 = %xmm0."
  "\n\t" "##  Clobbers %xmm1-%xmm4, %r11."
  "\n\t" "##"
  "\n\t" ".Laes_schedule_round:"
  "\n\t" "	# extract rcon from xmm8"
  "\n\t" "	pxor	%xmm1,	%xmm1"
  "\n\t" "	palignr	$15,	%xmm8,	%xmm1"
  "\n\t" "	palignr	$15,	%xmm8,	%xmm8"
  "\n\t" "	pxor	%xmm1,	%xmm7"

  "\n\t" "	# rotate"
  "\n\t" "	pshufd	$0xFF,	%xmm0,	%xmm0"
  "\n\t" "	palignr	$1,	%xmm0,	%xmm0"

  "\n\t" "	# fall through..."

  "\n\t" "	# low round: same as high round, but no rotation and no rcon."
  "\n\t" ".Laes_schedule_low_round:"
  "\n\t" "	# smear xmm7"
  "\n\t" "	movdqa	%xmm7,	%xmm1"
  "\n\t" "	pslldq	$4,	%xmm7"
  "\n\t" "	pxor	%xmm1,	%xmm7"
  "\n\t" "	movdqa	%xmm7,	%xmm1"
  "\n\t" "	pslldq	$8,	%xmm7"
  "\n\t" "	pxor	%xmm1,	%xmm7"
  "\n\t" "	pxor	.Lk_s63(%r10), %xmm7"

  "\n\t" "	# subbytes"
  "\n\t" "	movdqa  %xmm9, 	%xmm1"
  "\n\t" "	pandn	%xmm0, 	%xmm1"
  "\n\t" "	psrld	$4,    	%xmm1		# 1 = i"
  "\n\t" "	pand	%xmm9, 	%xmm0		# 0 = k"
  "\n\t" "	movdqa	%xmm11, %xmm2		# 2 : a/k"
  "\n\t" "	pshufb  %xmm0,  %xmm2		# 2 = a/k"
  "\n\t" "	pxor	%xmm1,	%xmm0		# 0 = j"
  "\n\t" "	movdqa  %xmm10,	%xmm3		# 3 : 1/i"
  "\n\t" "	pshufb  %xmm1, 	%xmm3		# 3 = 1/i"
  "\n\t" "	pxor	%xmm2, 	%xmm3		# 3 = iak = 1/i + a/k"
  "\n\t" "	movdqa	%xmm10,	%xmm4		# 4 : 1/j"
  "\n\t" "	pshufb	%xmm0, 	%xmm4		# 4 = 1/j"
  "\n\t" "	pxor	%xmm2, 	%xmm4		# 4 = jak = 1/j + a/k"
  "\n\t" "	movdqa  %xmm10,	%xmm2		# 2 : 1/iak"
  "\n\t" "	pshufb  %xmm3,	%xmm2		# 2 = 1/iak"
  "\n\t" "	pxor	%xmm0, 	%xmm2		# 2 = io"
  "\n\t" "	movdqa  %xmm10, %xmm3		# 3 : 1/jak"
  "\n\t" "	pshufb  %xmm4,  %xmm3		# 3 = 1/jak"
  "\n\t" "	pxor	%xmm1,  %xmm3		# 3 = jo"
  "\n\t" "	movdqa	.Lk_sb1(%r10), %xmm4	# 4 : sbou"
  "\n\t" "	pshufb  %xmm2,  %xmm4		# 4 = sbou"
  "\n\t" "	movdqa	.Lk_sb1+16(%r10), %xmm0	# 0 : sbot"
  "\n\t" "	pshufb  %xmm3,	%xmm0		# 0 = sb1t"
  "\n\t" "	pxor	%xmm4, 	%xmm0		# 0 = sbox output"

  "\n\t" "	# add in smeared stuff"
  "\n\t" "	pxor	%xmm7,	%xmm0	"
  "\n\t" "	movdqa	%xmm0,	%xmm7"
  "\n\t" "	ret"

  "\n\t" "##"
  "\n\t" "##  .Laes_schedule_transform"
  "\n\t" "##"
  "\n\t" "##  Linear-transform %xmm0 according to tables at (%r11)"
  "\n\t" "##"
  "\n\t" "##  Requires that %xmm9 = 0x0F0F... as in preheat"
  "\n\t" "##  Output in %xmm0"
  "\n\t" "##  Clobbers %xmm1, %xmm2"
  "\n\t" "##"
  "\n\t" ".Laes_schedule_transform:"
  "\n\t" "	movdqa	%xmm9,	%xmm1"
  "\n\t" "	pandn	%xmm0,	%xmm1"
  "\n\t" "	psrld	$4,	%xmm1"
  "\n\t" "	pand	%xmm9,	%xmm0"
  "\n\t" "	movdqa	(%r11), %xmm2 	# lo"
  "\n\t" "	pshufb	%xmm0,	%xmm2"
  "\n\t" "	movdqa	16(%r11), %xmm0 # hi"
  "\n\t" "	pshufb	%xmm1,	%xmm0"
  "\n\t" "	pxor	%xmm2,	%xmm0"
  "\n\t" "	ret"

  "\n\t" "##"
  "\n\t" "##  .Laes_schedule_mangle"
  "\n\t" "##"
  "\n\t" "##  Mangle xmm0 from (basis-transformed) standard version"
  "\n\t" "##  to our version."
  "\n\t" "##"
  "\n\t" "##  On encrypt,"
  "\n\t" "##    xor with 0x63"
  "\n\t" "##    multiply by circulant 0,1,1,1"
  "\n\t" "##    apply shiftrows transform"
  "\n\t" "##"
  "\n\t" "##  On decrypt,"
  "\n\t" "##    xor with 0x63"
  "\n\t" "##    multiply by 'inverse mixcolumns' circulant E,B,D,9"
  "\n\t" "##    deskew"
  "\n\t" "##    apply shiftrows transform"
  "\n\t" "##"
  "\n\t" "##"
  "\n\t" "##  Writes out to (%rdx), and increments or decrements it"
  "\n\t" "##  Keeps track of round number mod 4 in %r8"
  "\n\t" "##  Preserves xmm0"
  "\n\t" "##  Clobbers xmm1-xmm5"
  "\n\t" "##"
  "\n\t" ".Laes_schedule_mangle:"
  "\n\t" "	movdqa	%xmm0,	%xmm4	# save xmm0 for later"
  "\n\t" "	movdqa	.Lk_mc_forward(%r10),%xmm5"
  "\n\t" "	test	%rcx, 	%rcx"
  "\n\t" "	jnz	.Laes_schedule_mangle_dec"

  "\n\t" "	# encrypting"
  "\n\t" "	add	$16,	%rdx"
  "\n\t" "	pxor	.Lk_s63(%r10),%xmm4"
  "\n\t" "	pshufb	%xmm5,	%xmm4"
  "\n\t" "	movdqa	%xmm4,	%xmm3"
  "\n\t" "	pshufb	%xmm5,	%xmm4"
  "\n\t" "	pxor	%xmm4,	%xmm3"
  "\n\t" "	pshufb	%xmm5,	%xmm4"
  "\n\t" "	pxor	%xmm4,	%xmm3"

  "\n\t" "	jmp	.Laes_schedule_mangle_both"

  "\n\t" ".Laes_schedule_mangle_dec:"
  "\n\t" "	lea	.Lk_dks_1(%r10), %r11	# first table: *9"
  "\n\t" "	call 	.Laes_schedule_transform"
  "\n\t" "	movdqa	%xmm0,	%xmm3"
  "\n\t" "	pshufb	%xmm5,	%xmm3"

  "\n\t" "	add	$32, 	%r11		# next table:  *B"
  "\n\t" "	call 	.Laes_schedule_transform"
  "\n\t" "	pxor	%xmm0,	%xmm3"
  "\n\t" "	pshufb	%xmm5,	%xmm3"

  "\n\t" "	add	$32, 	%r11		# next table:  *D"
  "\n\t" "	call 	.Laes_schedule_transform"
  "\n\t" "	pxor	%xmm0,	%xmm3"
  "\n\t" "	pshufb	%xmm5,	%xmm3"

  "\n\t" "	add	$32, 	%r11		# next table:  *E"
  "\n\t" "	call 	.Laes_schedule_transform"
  "\n\t" "	pxor	%xmm0,	%xmm3"
  "\n\t" "	pshufb	%xmm5,	%xmm3"

  "\n\t" "	movdqa	%xmm4,	%xmm0		# restore %xmm0"
  "\n\t" "	add	$-16,	%rdx"

  "\n\t" ".Laes_schedule_mangle_both:"
  "\n\t" "	pshufb	.Lk_sr(%r8,%r10),%xmm3"
  "\n\t" "	add	$-16,	%r8"
  "\n\t" "	and	$48,	%r8"
  "\n\t" "	movdqa	%xmm3,	(%rdx)"
  "\n\t" "	ret"

  "\n\t" "##"
  "\n\t" "##  .Laes_schedule_mangle_last"
  "\n\t" "##"
  "\n\t" "##  Mangler for last round of key schedule"
  "\n\t" "##  Mangles %xmm0"
  "\n\t" "##    when encrypting, outputs out(%xmm0) ^ 63"
  "\n\t" "##    when decrypting, outputs unskew(%xmm0)"
  "\n\t" "##"
  "\n\t" "##  Always called right before return... jumps to cleanup and exits"
  "\n\t" "##"
  "\n\t" ".Laes_schedule_mangle_last:"
  "\n\t" "	# schedule last round key from xmm0"
  "\n\t" "	lea	.Lk_deskew(%r10),%r11	# prepare to deskew"
  "\n\t" "	test	%rcx, 	%rcx"
  "\n\t" "	jnz	.Laes_schedule_mangle_last_dec"

  "\n\t" "	# encrypting"
  "\n\t" "	pshufb	.Lk_sr(%r8,%r10),%xmm0	# output permute"
  "\n\t" "	lea	.Lk_opt(%r10),	%r11	# prepare to output transform"
  "\n\t" "	add	$32,	%rdx"

  "\n\t" ".Laes_schedule_mangle_last_dec:"
  "\n\t" "	add	$-16,	%rdx"
  "\n\t" "	pxor	.Lk_s63(%r10),	%xmm0"
  "\n\t" "	call	.Laes_schedule_transform # output transform"
  "\n\t" "	movdqa	%xmm0,	(%rdx)		# save last key"

  "\n\t" "	#_aes_cleanup"
  "\n\t" "	pxor	%xmm0,  %xmm0"
  "\n\t" "	pxor	%xmm1,  %xmm1"
  "\n\t" "	pxor	%xmm2,  %xmm2"
  "\n\t" "	pxor	%xmm3,  %xmm3"
  "\n\t" "	pxor	%xmm4,  %xmm4"
  "\n\t" "	pxor	%xmm5,  %xmm5"
  "\n\t" "	pxor	%xmm6,  %xmm6"
  "\n\t" "	pxor	%xmm7,  %xmm7"
  "\n\t" "	pxor	%xmm8,  %xmm8"
  "\n\t" "	ret"
X("\n\t" ".size _aes_schedule_core,.-_aes_schedule_core")

  "\n\t" "########################################################"
  "\n\t" "##                                                    ##"
  "\n\t" "##                     Constants                      ##"
  "\n\t" "##                                                    ##"
  "\n\t" "########################################################"

  "\n\t" ".align 16"
X("\n\t" ".type _aes_consts,@object")
  "\n\t" ".Laes_consts:"
  "\n\t" "_aes_consts:"
  "\n\t" "	# s0F"
  "\n\t" "	.Lk_s0F = .-.Laes_consts"
  "\n\t" "	.quad	0x0F0F0F0F0F0F0F0F"
  "\n\t" "	.quad	0x0F0F0F0F0F0F0F0F"

  "\n\t" "	# input transform (lo, hi)"
  "\n\t" "	.Lk_ipt = .-.Laes_consts"
  "\n\t" "	.quad	0xC2B2E8985A2A7000"
  "\n\t" "	.quad	0xCABAE09052227808"
  "\n\t" "	.quad	0x4C01307D317C4D00"
  "\n\t" "	.quad	0xCD80B1FCB0FDCC81"

  "\n\t" "	# inv, inva"
  "\n\t" "	.Lk_inv = .-.Laes_consts"
  "\n\t" "	.quad	0x0E05060F0D080180"
  "\n\t" "	.quad	0x040703090A0B0C02"
  "\n\t" "	.quad	0x01040A060F0B0780"
  "\n\t" "	.quad	0x030D0E0C02050809"

  "\n\t" "	# sb1u, sb1t"
  "\n\t" "	.Lk_sb1 = .-.Laes_consts"
  "\n\t" "	.quad	0xB19BE18FCB503E00"
  "\n\t" "	.quad	0xA5DF7A6E142AF544"
  "\n\t" "	.quad	0x3618D415FAE22300"
  "\n\t" "	.quad	0x3BF7CCC10D2ED9EF"


  "\n\t" "	# sb2u, sb2t"
  "\n\t" "	.Lk_sb2 = .-.Laes_consts"
  "\n\t" "	.quad	0xE27A93C60B712400"
  "\n\t" "	.quad	0x5EB7E955BC982FCD"
  "\n\t" "	.quad	0x69EB88400AE12900"
  "\n\t" "	.quad	0xC2A163C8AB82234A"

  "\n\t" "	# sbou, sbot"
  "\n\t" "	.Lk_sbo = .-.Laes_consts"
  "\n\t" "	.quad	0xD0D26D176FBDC700"
  "\n\t" "	.quad	0x15AABF7AC502A878"
  "\n\t" "	.quad	0xCFE474A55FBB6A00"
  "\n\t" "	.quad	0x8E1E90D1412B35FA"

  "\n\t" "	# mc_forward"
  "\n\t" "	.Lk_mc_forward = .-.Laes_consts"
  "\n\t" "	.quad	0x0407060500030201"
  "\n\t" "	.quad	0x0C0F0E0D080B0A09"
  "\n\t" "	.quad	0x080B0A0904070605"
  "\n\t" "	.quad	0x000302010C0F0E0D"
  "\n\t" "	.quad	0x0C0F0E0D080B0A09"
  "\n\t" "	.quad	0x0407060500030201"
  "\n\t" "	.quad	0x000302010C0F0E0D"
  "\n\t" "	.quad	0x080B0A0904070605"

  "\n\t" "	# mc_backward"
  "\n\t" "	.Lk_mc_backward = .-.Laes_consts"
  "\n\t" "	.quad	0x0605040702010003"
  "\n\t" "	.quad	0x0E0D0C0F0A09080B"
  "\n\t" "	.quad	0x020100030E0D0C0F"
  "\n\t" "	.quad	0x0A09080B06050407"
  "\n\t" "	.quad	0x0E0D0C0F0A09080B"
  "\n\t" "	.quad	0x0605040702010003"
  "\n\t" "	.quad	0x0A09080B06050407"
  "\n\t" "	.quad	0x020100030E0D0C0F"

  "\n\t" "	# sr"
  "\n\t" "	.Lk_sr = .-.Laes_consts"
  "\n\t" "	.quad	0x0706050403020100"
  "\n\t" "	.quad	0x0F0E0D0C0B0A0908"
  "\n\t" "	.quad	0x030E09040F0A0500"
  "\n\t" "	.quad	0x0B06010C07020D08"
  "\n\t" "	.quad	0x0F060D040B020900"
  "\n\t" "	.quad	0x070E050C030A0108"
  "\n\t" "	.quad	0x0B0E0104070A0D00"
  "\n\t" "	.quad	0x0306090C0F020508"

  "\n\t" "	# rcon"
  "\n\t" "	.Lk_rcon = .-.Laes_consts"
  "\n\t" "	.quad	0x1F8391B9AF9DEEB6"
  "\n\t" "	.quad	0x702A98084D7C7D81"

  "\n\t" "	# s63: all equal to 0x63 transformed"
  "\n\t" "	.Lk_s63 = .-.Laes_consts"
  "\n\t" "	.quad	0x5B5B5B5B5B5B5B5B"
  "\n\t" "	.quad	0x5B5B5B5B5B5B5B5B"

  "\n\t" "	# output transform"
  "\n\t" "	.Lk_opt = .-.Laes_consts"
  "\n\t" "	.quad	0xFF9F4929D6B66000"
  "\n\t" "	.quad	0xF7974121DEBE6808"
  "\n\t" "	.quad	0x01EDBD5150BCEC00"
  "\n\t" "	.quad	0xE10D5DB1B05C0CE0"

  "\n\t" "	# deskew tables: inverts the sbox's 'skew'"
  "\n\t" "	.Lk_deskew = .-.Laes_consts"
  "\n\t" "	.quad	0x07E4A34047A4E300"
  "\n\t" "	.quad	0x1DFEB95A5DBEF91A"
  "\n\t" "	.quad	0x5F36B5DC83EA6900"
  "\n\t" "	.quad	0x2841C2ABF49D1E77"

  "\n\t" "##"
  "\n\t" "##  Decryption stuff"
  "\n\t" "##  Key schedule constants"
  "\n\t" "##"
  "\n\t" "	# decryption key schedule: x -> invskew x*9"
  "\n\t" "	.Lk_dks_1 = .-.Laes_consts"
  "\n\t" "	.quad	0xB6116FC87ED9A700"
  "\n\t" "	.quad	0x4AED933482255BFC"
  "\n\t" "	.quad	0x4576516227143300"
  "\n\t" "	.quad	0x8BB89FACE9DAFDCE"

  "\n\t" "	# decryption key schedule: invskew x*9 -> invskew x*D"
  "\n\t" "	.Lk_dks_2 = .-.Laes_consts"
  "\n\t" "	.quad	0x27438FEBCCA86400"
  "\n\t" "	.quad	0x4622EE8AADC90561"
  "\n\t" "	.quad	0x815C13CE4F92DD00"
  "\n\t" "	.quad	0x73AEE13CBD602FF2"

  "\n\t" "	# decryption key schedule: invskew x*D -> invskew x*B"
  "\n\t" "	.Lk_dks_3 = .-.Laes_consts"
  "\n\t" "	.quad	0x03C4C50201C6C700"
  "\n\t" "	.quad	0xF83F3EF9FA3D3CFB"
  "\n\t" "	.quad	0xEE1921D638CFF700"
  "\n\t" "	.quad	0xA5526A9D7384BC4B"

  "\n\t" "	# decryption key schedule: invskew x*B -> invskew x*E + 0x63"
  "\n\t" "	.Lk_dks_4 = .-.Laes_consts"
  "\n\t" "	.quad	0xE3C390B053732000"
  "\n\t" "	.quad	0xA080D3F310306343"
  "\n\t" "	.quad	0xA0CA214B036982E8"
  "\n\t" "	.quad	0x2F45AEC48CE60D67"

  "\n\t" "##"
  "\n\t" "##  Decryption stuff"
  "\n\t" "##  Round function constants"
  "\n\t" "##"
  "\n\t" "	# decryption input transform"
  "\n\t" "	.Lk_dipt = .-.Laes_consts"
  "\n\t" "	.quad	0x0F505B040B545F00"
  "\n\t" "	.quad	0x154A411E114E451A"
  "\n\t" "	.quad	0x86E383E660056500"
  "\n\t" "	.quad	0x12771772F491F194"

  "\n\t" "	# decryption sbox output *9*u, *9*t"
  "\n\t" "	.Lk_dsb9 = .-.Laes_consts"
  "\n\t" "	.quad	0x851C03539A86D600"
  "\n\t" "	.quad	0xCAD51F504F994CC9"
  "\n\t" "	.quad	0xC03B1789ECD74900"
  "\n\t" "	.quad	0x725E2C9EB2FBA565"

  "\n\t" "	# decryption sbox output *D*u, *D*t"
  "\n\t" "	.Lk_dsbd = .-.Laes_consts"
  "\n\t" "	.quad	0x7D57CCDFE6B1A200"
  "\n\t" "	.quad	0xF56E9B13882A4439"
  "\n\t" "	.quad	0x3CE2FAF724C6CB00"
  "\n\t" "	.quad	0x2931180D15DEEFD3"

  "\n\t" "	# decryption sbox output *B*u, *B*t"
  "\n\t" "	.Lk_dsbb = .-.Laes_consts"
  "\n\t" "	.quad	0xD022649296B44200"
  "\n\t" "	.quad	0x602646F6B0F2D404"
  "\n\t" "	.quad	0xC19498A6CD596700"
  "\n\t" "	.quad	0xF3FF0C3E3255AA6B"

  "\n\t" "	# decryption sbox output *E*u, *E*t"
  "\n\t" "	.Lk_dsbe = .-.Laes_consts"
  "\n\t" "	.quad	0x46F2929626D4D000"
  "\n\t" "	.quad	0x2242600464B4F6B0"
  "\n\t" "	.quad	0x0C55A6CDFFAAC100"
  "\n\t" "	.quad	0x9467F36B98593E32"

  "\n\t" "	# decryption sbox final output"
  "\n\t" "	.Lk_dsbo = .-.Laes_consts"
  "\n\t" "	.quad	0x1387EA537EF94000"
  "\n\t" "	.quad	0xC7AA6DB9D4943E2D"
  "\n\t" "	.quad	0x12D7560F93441D00"
  "\n\t" "	.quad	0xCA4B8159D8C58E9C"
X("\n\t" ".size _aes_consts,.-_aes_consts")
);

#endif /* USE_SSSE3 */
