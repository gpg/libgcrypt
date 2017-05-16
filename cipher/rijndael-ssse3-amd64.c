/* SSSE3 vector permutation AES for Libgcrypt
 * Copyright (C) 2014-2017 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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


/* Assembly functions in rijndael-ssse3-amd64-asm.S. Note that these
   have custom calling convention and need to be called from assembly
   blocks, not directly. */
extern void _gcry_aes_ssse3_enc_preload(void);
extern void _gcry_aes_ssse3_dec_preload(void);
extern void _gcry_aes_ssse3_schedule_core(void);
extern void _gcry_aes_ssse3_encrypt_core(void);
extern void _gcry_aes_ssse3_decrypt_core(void);



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
# define PUSH_STACK_PTR
# define POP_STACK_PTR
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
/* Old GCC versions use red-zone of AMD64 SYSV ABI and stack pointer is
 * not properly adjusted for assembly block. Therefore stack pointer
 * needs to be manually corrected. */
# define PUSH_STACK_PTR "subq $128, %%rsp;\n\t"
# define POP_STACK_PTR  "addq $128, %%rsp;\n\t"
#endif

#define vpaes_ssse3_prepare_enc() \
    vpaes_ssse3_prepare(); \
    asm volatile (PUSH_STACK_PTR \
                  "callq *%q[core] \n\t" \
                  POP_STACK_PTR \
                  : \
                  : [core] "r" (_gcry_aes_ssse3_enc_preload) \
                  : "rax", "cc", "memory" )

#define vpaes_ssse3_prepare_dec() \
    vpaes_ssse3_prepare(); \
    asm volatile (PUSH_STACK_PTR \
                  "callq *%q[core] \n\t" \
                  POP_STACK_PTR \
                  : \
                  : [core] "r" (_gcry_aes_ssse3_dec_preload) \
                  : "rax", "cc", "memory" )



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
                PUSH_STACK_PTR
                "callq *%q[core]"			"\n\t"
                POP_STACK_PTR
                :
                : [core] "r" (&_gcry_aes_ssse3_schedule_core),
                  [key] "m" (*key),
                  [bits] "g" (keybits),
                  [buf] "m" (ctx->keyschenc32[0][0]),
                  [dir] "g" (0),
                  [rotoffs] "g" (48)
                : "r8", "r9", "r10", "r11", "rax", "rcx", "rdx", "rdi", "rsi",
                  "cc", "memory");

  /* Save key for setting up decryption. */
  if (keybits > 192)
    asm volatile ("movdqu   (%[src]), %%xmm0\n\t"
		  "movdqu 16(%[src]), %%xmm1\n\t"
		  "movdqu %%xmm0,   (%[dst])\n\t"
		  "movdqu %%xmm1, 16(%[dst])\n\t"
		  : /* No output */
		  : [dst] "r" (&ctx->keyschdec32[0][0]), [src] "r" (key)
		  : "memory" );
  else if (keybits == 192)
    asm volatile ("movdqu   (%[src]), %%xmm0\n\t"
		  "movq   16(%[src]), %%xmm1\n\t"
		  "movdqu %%xmm0,   (%[dst])\n\t"
		  "movq   %%xmm1, 16(%[dst])\n\t"
		  : /* No output */
		  : [dst] "r" (&ctx->keyschdec32[0][0]), [src] "r" (key)
		  : "memory" );
  else
    asm volatile ("movdqu (%[src]), %%xmm0\n\t"
		  "movdqu %%xmm0, (%[dst])\n\t"
		  : /* No output */
		  : [dst] "r" (&ctx->keyschdec32[0][0]), [src] "r" (key)
		  : "memory" );

  vpaes_ssse3_cleanup();
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
                PUSH_STACK_PTR
                "callq *%q[core]"			"\n\t"
                POP_STACK_PTR
                :
                : [core] "r" (_gcry_aes_ssse3_schedule_core),
                  [key] "m" (ctx->keyschdec32[0][0]),
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
do_vpaes_ssse3_enc (const RIJNDAEL_context *ctx, unsigned int nrounds)
{
  unsigned int middle_rounds = nrounds - 1;
  const void *keysched = ctx->keyschenc32;

  asm volatile (PUSH_STACK_PTR
		"callq *%q[core]"			"\n\t"
		POP_STACK_PTR
		: "+a" (middle_rounds), "+d" (keysched)
		: [core] "r" (_gcry_aes_ssse3_encrypt_core)
		: "rcx", "rsi", "rdi", "cc", "memory");
}


/* Decrypt one block using the Intel SSSE3 instructions.  Block is input
* and output through SSE register xmm0. */
static inline void
do_vpaes_ssse3_dec (const RIJNDAEL_context *ctx, unsigned int nrounds)
{
  unsigned int middle_rounds = nrounds - 1;
  const void *keysched = ctx->keyschdec32;

  asm volatile (PUSH_STACK_PTR
		"callq *%q[core]"			"\n\t"
		POP_STACK_PTR
		: "+a" (middle_rounds), "+d" (keysched)
		: [core] "r" (_gcry_aes_ssse3_decrypt_core)
		: "rcx", "rsi", "cc", "memory");
}


unsigned int
_gcry_aes_ssse3_encrypt (const RIJNDAEL_context *ctx, unsigned char *dst,
                        const unsigned char *src)
{
  unsigned int nrounds = ctx->rounds;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc ();
  asm volatile ("movdqu %[src], %%xmm0\n\t"
                :
                : [src] "m" (*src)
                : "memory" );
  do_vpaes_ssse3_enc (ctx, nrounds);
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
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc ();

  asm volatile ("movdqu %[iv], %%xmm0\n\t"
                : /* No output */
                : [iv] "m" (*iv)
                : "memory" );

  for ( ;nblocks; nblocks-- )
    {
      do_vpaes_ssse3_enc (ctx, nrounds);

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
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc ();

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

      do_vpaes_ssse3_enc (ctx, nrounds);

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
  byte ssse3_state[SSSE3_STATE_SIZE];
  u64 ctrlow;

  vpaes_ssse3_prepare_enc ();

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
                    : [ctrlow] "+r" (ctrlow)
                    :
                    : "cc", "memory");

      do_vpaes_ssse3_enc (ctx, nrounds);

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
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_dec ();
  asm volatile ("movdqu %[src], %%xmm0\n\t"
                :
                : [src] "m" (*src)
                : "memory" );
  do_vpaes_ssse3_dec (ctx, nrounds);
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
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc ();

  asm volatile ("movdqu %[iv], %%xmm0\n\t"
                : /* No output */
                : [iv] "m" (*iv)
                : "memory" );

  for ( ;nblocks; nblocks-- )
    {
      do_vpaes_ssse3_enc (ctx, nrounds);

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
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_dec ();

  asm volatile ("movdqu %[iv], %%xmm7\n\t"	/* use xmm7 as fast IV storage */
		: /* No output */
		: [iv] "m" (*iv)
		: "memory");

  for ( ;nblocks; nblocks-- )
    {
      asm volatile ("movdqu %[inbuf], %%xmm0\n\t"
		    "movdqa %%xmm0, %%xmm6\n\t"    /* use xmm6 as savebuf */
		    : /* No output */
		    : [inbuf] "m" (*inbuf)
		    : "memory");

      do_vpaes_ssse3_dec (ctx, nrounds);

      asm volatile ("pxor %%xmm7, %%xmm0\n\t"	/* xor IV with output */
		    "movdqu %%xmm0, %[outbuf]\n\t"
		    "movdqu %%xmm6, %%xmm7\n\t"	/* store savebuf as new IV */
		    : [outbuf] "=m" (*outbuf)
		    :
		    : "memory");

      outbuf += BLOCKSIZE;
      inbuf  += BLOCKSIZE;
    }

  asm volatile ("movdqu %%xmm7, %[iv]\n\t"	/* store IV */
		: /* No output */
		: [iv] "m" (*iv)
		: "memory");

  vpaes_ssse3_cleanup ();
}


static void
ssse3_ocb_enc (gcry_cipher_hd_t c, void *outbuf_arg,
               const void *inbuf_arg, size_t nblocks)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  u64 n = c->u_mode.ocb.data_nblocks;
  unsigned int nrounds = ctx->rounds;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc ();

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

      l = ocb_get_l(c, ++n);

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

      do_vpaes_ssse3_enc (ctx, nrounds);

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

  vpaes_ssse3_cleanup ();
}

static void
ssse3_ocb_dec (gcry_cipher_hd_t c, void *outbuf_arg,
               const void *inbuf_arg, size_t nblocks)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  u64 n = c->u_mode.ocb.data_nblocks;
  unsigned int nrounds = ctx->rounds;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_dec ();

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

      l = ocb_get_l(c, ++n);

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

      do_vpaes_ssse3_dec (ctx, nrounds);

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
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  const unsigned char *abuf = abuf_arg;
  u64 n = c->u_mode.ocb.aad_nblocks;
  unsigned int nrounds = ctx->rounds;
  byte ssse3_state[SSSE3_STATE_SIZE];

  vpaes_ssse3_prepare_enc ();

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

      l = ocb_get_l(c, ++n);

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

      do_vpaes_ssse3_enc (ctx, nrounds);

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

  vpaes_ssse3_cleanup ();
}

#endif /* USE_SSSE3 */
