/* chacha20.c  -  Bernstein's ChaCha20 cipher
 * Copyright (C) 2014 Jussi Kivilinna <jussi.kivilinna@iki.fi>
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
 *
 * For a description of the algorithm, see:
 *   http://cr.yp.to/chacha.html
 */

/* The code is based on salsa20.c and public-domain ChaCha implementations:
 *  chacha-ref.c version 20080118
 *  D. J. Bernstein
 *  Public domain.
 * and
 *  Andrew Moon
 *  https://github.com/floodyberry/chacha-opt
 */


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"


#define CHACHA20_MIN_KEY_SIZE 16        /* Bytes.  */
#define CHACHA20_MAX_KEY_SIZE 32        /* Bytes.  */
#define CHACHA20_BLOCK_SIZE   64        /* Bytes.  */
#define CHACHA20_MIN_IV_SIZE   8        /* Bytes.  */
#define CHACHA20_MAX_IV_SIZE  12        /* Bytes.  */
#define CHACHA20_CTR_SIZE     16        /* Bytes.  */
#define CHACHA20_INPUT_LENGTH (CHACHA20_BLOCK_SIZE / 4)

/* USE_SSE2 indicates whether to compile with Intel SSE2 code. */
#undef USE_SSE2
#if defined(__x86_64__) && (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS))
# define USE_SSE2 1
#endif

/* USE_SSSE3 indicates whether to compile with Intel SSSE3 code. */
#undef USE_SSSE3
#if defined(__x86_64__) && (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS)) && \
    defined(HAVE_GCC_INLINE_ASM_SSSE3)
# define USE_SSSE3 1
#endif

/* USE_AVX2 indicates whether to compile with Intel AVX2 code. */
#undef USE_AVX2
#if defined(__x86_64__) && (defined(HAVE_COMPATIBLE_GCC_AMD64_PLATFORM_AS) || \
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS)) && \
    defined(ENABLE_AVX2_SUPPORT)
# define USE_AVX2 1
#endif

/* USE_NEON indicates whether to enable ARM NEON assembly code. */
#undef USE_NEON
#ifdef ENABLE_NEON_SUPPORT
# if defined(HAVE_ARM_ARCH_V6) && defined(__ARMEL__) \
     && defined(HAVE_COMPATIBLE_GCC_ARM_PLATFORM_AS) \
     && defined(HAVE_GCC_INLINE_ASM_NEON)
#  define USE_NEON 1
# endif
#endif /*ENABLE_NEON_SUPPORT*/


struct CHACHA20_context_s;


/* Assembly implementations use SystemV ABI, ABI conversion and additional
 * stack to store XMM6-XMM15 needed on Win64. */
#undef ASM_FUNC_ABI
#undef ASM_EXTRA_STACK
#if (defined(USE_SSE2) || defined(USE_SSSE3) || defined(USE_AVX2)) && \
    defined(HAVE_COMPATIBLE_GCC_WIN64_PLATFORM_AS)
# define ASM_FUNC_ABI __attribute__((sysv_abi))
# define ASM_EXTRA_STACK (10 * 16)
#else
# define ASM_FUNC_ABI
# define ASM_EXTRA_STACK 0
#endif


typedef unsigned int (* chacha20_blocks_t)(u32 *state, const byte *src,
                                           byte *dst,
                                           size_t bytes) ASM_FUNC_ABI;

typedef struct CHACHA20_context_s
{
  u32 input[CHACHA20_INPUT_LENGTH];
  u32 pad[CHACHA20_INPUT_LENGTH];
  chacha20_blocks_t blocks;
  unsigned int unused; /* bytes in the pad.  */
} CHACHA20_context_t;


#ifdef USE_SSE2

unsigned int _gcry_chacha20_amd64_sse2_blocks(u32 *state, const byte *in,
                                              byte *out,
                                              size_t bytes) ASM_FUNC_ABI;

#endif /* USE_SSE2 */

#ifdef USE_SSSE3

unsigned int _gcry_chacha20_amd64_ssse3_blocks(u32 *state, const byte *in,
                                               byte *out,
                                               size_t bytes) ASM_FUNC_ABI;

#endif /* USE_SSSE3 */

#ifdef USE_AVX2

unsigned int _gcry_chacha20_amd64_avx2_blocks(u32 *state, const byte *in,
                                              byte *out,
                                              size_t bytes) ASM_FUNC_ABI;

#endif /* USE_AVX2 */

#ifdef USE_NEON

unsigned int _gcry_chacha20_armv7_neon_blocks(u32 *state, const byte *in,
                                              byte *out,
                                              size_t bytes) ASM_FUNC_ABI;

#endif /* USE_NEON */


static void chacha20_setiv (void *context, const byte * iv, size_t ivlen);
static const char *selftest (void);



#define QROUND(a,b,c,d)         \
  do {                          \
    a += b; d = rol(d ^ a, 16); \
    c += d; b = rol(b ^ c, 12); \
    a += b; d = rol(d ^ a, 8);  \
    c += d; b = rol(b ^ c, 7);  \
  } while (0)

#define QOUT(ai, bi, ci, di) \
  DO_OUT(ai); DO_OUT(bi); DO_OUT(ci); DO_OUT(di)


#ifndef USE_SSE2
ASM_FUNC_ABI static unsigned int
chacha20_blocks (u32 *state, const byte *src, byte *dst, size_t bytes)
{
  u32 pad[CHACHA20_INPUT_LENGTH];
  u32 inp[CHACHA20_INPUT_LENGTH];
  unsigned int i;

  /* Note: 'bytes' must be multiple of 64 and not zero. */

  inp[0] = state[0];
  inp[1] = state[1];
  inp[2] = state[2];
  inp[3] = state[3];
  inp[4] = state[4];
  inp[5] = state[5];
  inp[6] = state[6];
  inp[7] = state[7];
  inp[8] = state[8];
  inp[9] = state[9];
  inp[10] = state[10];
  inp[11] = state[11];
  inp[12] = state[12];
  inp[13] = state[13];
  inp[14] = state[14];
  inp[15] = state[15];

  do
    {
      /* First round. */
      pad[0] = inp[0];
      pad[4] = inp[4];
      pad[8] = inp[8];
      pad[12] = inp[12];
      QROUND (pad[0], pad[4], pad[8], pad[12]);
      pad[1] = inp[1];
      pad[5] = inp[5];
      pad[9] = inp[9];
      pad[13] = inp[13];
      QROUND (pad[1], pad[5], pad[9], pad[13]);
      pad[2] = inp[2];
      pad[6] = inp[6];
      pad[10] = inp[10];
      pad[14] = inp[14];
      QROUND (pad[2], pad[6], pad[10], pad[14]);
      pad[3] = inp[3];
      pad[7] = inp[7];
      pad[11] = inp[11];
      pad[15] = inp[15];
      QROUND (pad[3], pad[7], pad[11], pad[15]);

      QROUND (pad[0], pad[5], pad[10], pad[15]);
      QROUND (pad[1], pad[6], pad[11], pad[12]);
      QROUND (pad[2], pad[7], pad[8], pad[13]);
      QROUND (pad[3], pad[4], pad[9], pad[14]);

      for (i = 2; i < 20 - 2; i += 2)
      {
        QROUND (pad[0], pad[4], pad[8], pad[12]);
        QROUND (pad[1], pad[5], pad[9], pad[13]);
        QROUND (pad[2], pad[6], pad[10], pad[14]);
        QROUND (pad[3], pad[7], pad[11], pad[15]);

        QROUND (pad[0], pad[5], pad[10], pad[15]);
        QROUND (pad[1], pad[6], pad[11], pad[12]);
        QROUND (pad[2], pad[7], pad[8], pad[13]);
        QROUND (pad[3], pad[4], pad[9], pad[14]);
      }

      QROUND (pad[0], pad[4], pad[8], pad[12]);
      QROUND (pad[1], pad[5], pad[9], pad[13]);
      QROUND (pad[2], pad[6], pad[10], pad[14]);
      QROUND (pad[3], pad[7], pad[11], pad[15]);

      if (src)
        {
#define DO_OUT(idx) buf_put_le32(dst + (idx) * 4, \
                                 (pad[idx] + inp[idx]) ^ \
                                  buf_get_le32(src + (idx) * 4))
          /* Last round. */
          QROUND (pad[0], pad[5], pad[10], pad[15]);
          QOUT(0, 5, 10, 15);
          QROUND (pad[1], pad[6], pad[11], pad[12]);
          QOUT(1, 6, 11, 12);
          QROUND (pad[2], pad[7], pad[8], pad[13]);
          QOUT(2, 7, 8, 13);
          QROUND (pad[3], pad[4], pad[9], pad[14]);
          QOUT(3, 4, 9, 14);
#undef DO_OUT
        }
      else
        {
#define DO_OUT(idx) buf_put_le32(dst + (idx) * 4, pad[idx] + inp[idx])
          /* Last round. */
          QROUND (pad[0], pad[5], pad[10], pad[15]);
          QOUT(0, 5, 10, 15);
          QROUND (pad[1], pad[6], pad[11], pad[12]);
          QOUT(1, 6, 11, 12);
          QROUND (pad[2], pad[7], pad[8], pad[13]);
          QOUT(2, 7, 8, 13);
          QROUND (pad[3], pad[4], pad[9], pad[14]);
          QOUT(3, 4, 9, 14);
#undef DO_OUT
        }

      /* Update counter. */
      inp[13] += (!++inp[12]);

      bytes -= CHACHA20_BLOCK_SIZE;
      dst += CHACHA20_BLOCK_SIZE;
      src += (src) ? CHACHA20_BLOCK_SIZE : 0;
    }
  while (bytes >= CHACHA20_BLOCK_SIZE);

  state[12] = inp[12];
  state[13] = inp[13];

  /* burn_stack */
  return (2 * CHACHA20_INPUT_LENGTH * sizeof(u32) + 6 * sizeof(void *));
}
#endif /*!USE_SSE2*/

#undef QROUND
#undef QOUT


static unsigned int
chacha20_core(u32 *dst, struct CHACHA20_context_s *ctx)
{
  return ctx->blocks(ctx->input, NULL, (byte *)dst, CHACHA20_BLOCK_SIZE)
         + ASM_EXTRA_STACK;
}


static void
chacha20_keysetup (CHACHA20_context_t * ctx, const byte * key,
                   unsigned int keylen)
{
  /* These constants are the little endian encoding of the string
     "expand 32-byte k".  For the 128 bit variant, the "32" in that
     string will be fixed up to "16".  */
  ctx->input[0] = 0x61707865;        /* "apxe"  */
  ctx->input[1] = 0x3320646e;        /* "3 dn"  */
  ctx->input[2] = 0x79622d32;        /* "yb-2"  */
  ctx->input[3] = 0x6b206574;        /* "k et"  */

  ctx->input[4] = buf_get_le32 (key + 0);
  ctx->input[5] = buf_get_le32 (key + 4);
  ctx->input[6] = buf_get_le32 (key + 8);
  ctx->input[7] = buf_get_le32 (key + 12);

  if (keylen == CHACHA20_MAX_KEY_SIZE) /* 256 bits */
    {
      ctx->input[8] = buf_get_le32 (key + 16);
      ctx->input[9] = buf_get_le32 (key + 20);
      ctx->input[10] = buf_get_le32 (key + 24);
      ctx->input[11] = buf_get_le32 (key + 28);
    }
  else /* 128 bits */
    {
      ctx->input[8] = ctx->input[4];
      ctx->input[9] = ctx->input[5];
      ctx->input[10] = ctx->input[6];
      ctx->input[11] = ctx->input[7];

      ctx->input[1] -= 0x02000000;        /* Change to "1 dn".  */
      ctx->input[2] += 0x00000004;        /* Change to "yb-6".  */
    }
}


static void
chacha20_ivsetup (CHACHA20_context_t * ctx, const byte * iv, size_t ivlen)
{
  if (ivlen == CHACHA20_CTR_SIZE)
    {
      ctx->input[12] = buf_get_le32 (iv + 0);
      ctx->input[13] = buf_get_le32 (iv + 4);
      ctx->input[14] = buf_get_le32 (iv + 8);
      ctx->input[15] = buf_get_le32 (iv + 12);
    }
  else if (ivlen == CHACHA20_MAX_IV_SIZE)
    {
      ctx->input[12] = 0;
      ctx->input[13] = buf_get_le32 (iv + 0);
      ctx->input[14] = buf_get_le32 (iv + 4);
      ctx->input[15] = buf_get_le32 (iv + 8);
    }
  else if (ivlen == CHACHA20_MIN_IV_SIZE)
    {
      ctx->input[12] = 0;
      ctx->input[13] = 0;
      ctx->input[14] = buf_get_le32 (iv + 0);
      ctx->input[15] = buf_get_le32 (iv + 4);
    }
  else
    {
      ctx->input[12] = 0;
      ctx->input[13] = 0;
      ctx->input[14] = 0;
      ctx->input[15] = 0;
    }
}


static gcry_err_code_t
chacha20_do_setkey (CHACHA20_context_t * ctx,
                    const byte * key, unsigned int keylen)
{
  static int initialized;
  static const char *selftest_failed;
  unsigned int features = _gcry_get_hw_features ();

  if (!initialized)
    {
      initialized = 1;
      selftest_failed = selftest ();
      if (selftest_failed)
        log_error ("CHACHA20 selftest failed (%s)\n", selftest_failed);
    }
  if (selftest_failed)
    return GPG_ERR_SELFTEST_FAILED;

  if (keylen != CHACHA20_MAX_KEY_SIZE && keylen != CHACHA20_MIN_KEY_SIZE)
    return GPG_ERR_INV_KEYLEN;

#ifdef USE_SSE2
  ctx->blocks = _gcry_chacha20_amd64_sse2_blocks;
#else
  ctx->blocks = chacha20_blocks;
#endif

#ifdef USE_SSSE3
  if (features & HWF_INTEL_SSSE3)
    ctx->blocks = _gcry_chacha20_amd64_ssse3_blocks;
#endif
#ifdef USE_AVX2
  if (features & HWF_INTEL_AVX2)
    ctx->blocks = _gcry_chacha20_amd64_avx2_blocks;
#endif
#ifdef USE_NEON
  if (features & HWF_ARM_NEON)
    ctx->blocks = _gcry_chacha20_armv7_neon_blocks;
#endif

  (void)features;

  chacha20_keysetup (ctx, key, keylen);

  /* We default to a zero nonce.  */
  chacha20_setiv (ctx, NULL, 0);

  return 0;
}


static gcry_err_code_t
chacha20_setkey (void *context, const byte * key, unsigned int keylen)
{
  CHACHA20_context_t *ctx = (CHACHA20_context_t *) context;
  gcry_err_code_t rc = chacha20_do_setkey (ctx, key, keylen);
  _gcry_burn_stack (4 + sizeof (void *) + 4 * sizeof (void *));
  return rc;
}


static void
chacha20_setiv (void *context, const byte * iv, size_t ivlen)
{
  CHACHA20_context_t *ctx = (CHACHA20_context_t *) context;

  /* draft-nir-cfrg-chacha20-poly1305-02 defines 96-bit and 64-bit nonce. */
  if (iv && ivlen != CHACHA20_MAX_IV_SIZE && ivlen != CHACHA20_MIN_IV_SIZE
      && ivlen != CHACHA20_CTR_SIZE)
    log_info ("WARNING: chacha20_setiv: bad ivlen=%u\n", (u32) ivlen);

  if (iv && (ivlen == CHACHA20_MAX_IV_SIZE || ivlen == CHACHA20_MIN_IV_SIZE
             || ivlen == CHACHA20_CTR_SIZE))
    chacha20_ivsetup (ctx, iv, ivlen);
  else
    chacha20_ivsetup (ctx, NULL, 0);

  /* Reset the unused pad bytes counter.  */
  ctx->unused = 0;
}



/* Note: This function requires LENGTH > 0.  */
static void
chacha20_do_encrypt_stream (CHACHA20_context_t * ctx,
                            byte * outbuf, const byte * inbuf, size_t length)
{
  unsigned int nburn, burn = 0;

  if (ctx->unused)
    {
      unsigned char *p = (void *) ctx->pad;
      size_t n;

      gcry_assert (ctx->unused < CHACHA20_BLOCK_SIZE);

      n = ctx->unused;
      if (n > length)
        n = length;
      buf_xor (outbuf, inbuf, p + CHACHA20_BLOCK_SIZE - ctx->unused, n);
      length -= n;
      outbuf += n;
      inbuf += n;
      ctx->unused -= n;
      if (!length)
        return;
      gcry_assert (!ctx->unused);
    }

  if (length >= CHACHA20_BLOCK_SIZE)
    {
      size_t nblocks = length / CHACHA20_BLOCK_SIZE;
      size_t bytes = nblocks * CHACHA20_BLOCK_SIZE;
      burn = ctx->blocks(ctx->input, inbuf, outbuf, bytes);
      length -= bytes;
      outbuf += bytes;
      inbuf  += bytes;
    }

  if (length > 0)
    {
      nburn = chacha20_core (ctx->pad, ctx);
      burn = nburn > burn ? nburn : burn;

      buf_xor (outbuf, inbuf, ctx->pad, length);
      ctx->unused = CHACHA20_BLOCK_SIZE - length;
    }

  _gcry_burn_stack (burn);
}


static void
chacha20_encrypt_stream (void *context, byte * outbuf, const byte * inbuf,
                         size_t length)
{
  CHACHA20_context_t *ctx = (CHACHA20_context_t *) context;

  if (length)
    chacha20_do_encrypt_stream (ctx, outbuf, inbuf, length);
}


static const char *
selftest (void)
{
  byte ctxbuf[sizeof(CHACHA20_context_t) + 15];
  CHACHA20_context_t *ctx;
  byte scratch[127 + 1];
  byte buf[512 + 64 + 4];
  int i;

  /* From draft-strombergson-chacha-test-vectors */
  static byte key_1[] = {
    0xc4, 0x6e, 0xc1, 0xb1, 0x8c, 0xe8, 0xa8, 0x78,
    0x72, 0x5a, 0x37, 0xe7, 0x80, 0xdf, 0xb7, 0x35,
    0x1f, 0x68, 0xed, 0x2e, 0x19, 0x4c, 0x79, 0xfb,
    0xc6, 0xae, 0xbe, 0xe1, 0xa6, 0x67, 0x97, 0x5d
  };
  static const byte nonce_1[] =
    { 0x1a, 0xda, 0x31, 0xd5, 0xcf, 0x68, 0x82, 0x21 };
  static const byte plaintext_1[127] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };
  static const byte ciphertext_1[127] = {
    0xf6, 0x3a, 0x89, 0xb7, 0x5c, 0x22, 0x71, 0xf9,
    0x36, 0x88, 0x16, 0x54, 0x2b, 0xa5, 0x2f, 0x06,
    0xed, 0x49, 0x24, 0x17, 0x92, 0x30, 0x2b, 0x00,
    0xb5, 0xe8, 0xf8, 0x0a, 0xe9, 0xa4, 0x73, 0xaf,
    0xc2, 0x5b, 0x21, 0x8f, 0x51, 0x9a, 0xf0, 0xfd,
    0xd4, 0x06, 0x36, 0x2e, 0x8d, 0x69, 0xde, 0x7f,
    0x54, 0xc6, 0x04, 0xa6, 0xe0, 0x0f, 0x35, 0x3f,
    0x11, 0x0f, 0x77, 0x1b, 0xdc, 0xa8, 0xab, 0x92,
    0xe5, 0xfb, 0xc3, 0x4e, 0x60, 0xa1, 0xd9, 0xa9,
    0xdb, 0x17, 0x34, 0x5b, 0x0a, 0x40, 0x27, 0x36,
    0x85, 0x3b, 0xf9, 0x10, 0xb0, 0x60, 0xbd, 0xf1,
    0xf8, 0x97, 0xb6, 0x29, 0x0f, 0x01, 0xd1, 0x38,
    0xae, 0x2c, 0x4c, 0x90, 0x22, 0x5b, 0xa9, 0xea,
    0x14, 0xd5, 0x18, 0xf5, 0x59, 0x29, 0xde, 0xa0,
    0x98, 0xca, 0x7a, 0x6c, 0xcf, 0xe6, 0x12, 0x27,
    0x05, 0x3c, 0x84, 0xe4, 0x9a, 0x4a, 0x33
  };

  /* 16-byte alignment required for amd64 implementation. */
  ctx = (CHACHA20_context_t *)((uintptr_t)(ctxbuf + 15) & ~(uintptr_t)15);

  chacha20_setkey (ctx, key_1, sizeof key_1);
  chacha20_setiv (ctx, nonce_1, sizeof nonce_1);
  scratch[sizeof (scratch) - 1] = 0;
  chacha20_encrypt_stream (ctx, scratch, plaintext_1, sizeof plaintext_1);
  if (memcmp (scratch, ciphertext_1, sizeof ciphertext_1))
    return "ChaCha20 encryption test 1 failed.";
  if (scratch[sizeof (scratch) - 1])
    return "ChaCha20 wrote too much.";
  chacha20_setkey (ctx, key_1, sizeof (key_1));
  chacha20_setiv (ctx, nonce_1, sizeof nonce_1);
  chacha20_encrypt_stream (ctx, scratch, scratch, sizeof plaintext_1);
  if (memcmp (scratch, plaintext_1, sizeof plaintext_1))
    return "ChaCha20 decryption test 1 failed.";

  for (i = 0; i < sizeof buf; i++)
    buf[i] = i;
  chacha20_setkey (ctx, key_1, sizeof key_1);
  chacha20_setiv (ctx, nonce_1, sizeof nonce_1);
  /*encrypt */
  chacha20_encrypt_stream (ctx, buf, buf, sizeof buf);
  /*decrypt */
  chacha20_setkey (ctx, key_1, sizeof key_1);
  chacha20_setiv (ctx, nonce_1, sizeof nonce_1);
  chacha20_encrypt_stream (ctx, buf, buf, 1);
  chacha20_encrypt_stream (ctx, buf + 1, buf + 1, (sizeof buf) - 1 - 1);
  chacha20_encrypt_stream (ctx, buf + (sizeof buf) - 1,
                           buf + (sizeof buf) - 1, 1);
  for (i = 0; i < sizeof buf; i++)
    if (buf[i] != (byte) i)
      return "ChaCha20 encryption test 2 failed.";

  chacha20_setkey (ctx, key_1, sizeof key_1);
  chacha20_setiv (ctx, nonce_1, sizeof nonce_1);
  /* encrypt */
  for (i = 0; i < sizeof buf; i++)
    chacha20_encrypt_stream (ctx, &buf[i], &buf[i], 1);
  /* decrypt */
  chacha20_setkey (ctx, key_1, sizeof key_1);
  chacha20_setiv (ctx, nonce_1, sizeof nonce_1);
  chacha20_encrypt_stream (ctx, buf, buf, sizeof buf);
  for (i = 0; i < sizeof buf; i++)
    if (buf[i] != (byte) i)
      return "ChaCha20 encryption test 3 failed.";

  return NULL;
}


gcry_cipher_spec_t _gcry_cipher_spec_chacha20 = {
  GCRY_CIPHER_CHACHA20,
  {0, 0},                       /* flags */
  "CHACHA20",                   /* name */
  NULL,                         /* aliases */
  NULL,                         /* oids */
  1,                            /* blocksize in bytes. */
  CHACHA20_MAX_KEY_SIZE * 8,    /* standard key length in bits. */
  sizeof (CHACHA20_context_t),
  chacha20_setkey,
  NULL,
  NULL,
  chacha20_encrypt_stream,
  chacha20_encrypt_stream,
  NULL,
  NULL,
  chacha20_setiv
};
