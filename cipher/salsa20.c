/* salsa20.c  -  Bernstein's Salsa20 cipher
 * Copyright (C) 2012 Simon Josefsson, Niels Möller
 * Copyright (C) 2013 g10 Code GmbH
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
 *   http://cr.yp.to/snuffle/spec.pdf
 *   http://cr.yp.to/snuffle/design.pdf
 */

/* The code is based on the code in Nettle
   (git commit id 9d2d8ddaee35b91a4e1a32ae77cba04bea3480e7)
   which in turn is based on
   salsa20-ref.c version 20051118
   D. J. Bernstein
   Public domain.
*/


#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"
#include "g10lib.h"
#include "cipher.h"
#include "bufhelp.h"

#define SALSA20_MIN_KEY_SIZE 16  /* Bytes.  */
#define SALSA20_MAX_KEY_SIZE 32  /* Bytes.  */
#define SALSA20_BLOCK_SIZE   64  /* Bytes.  */
#define SALSA20_IV_SIZE       8  /* Bytes.  */
#define SALSA20_INPUT_LENGTH 16  /* Bytes.  */

/* Number of rounds.  The standard uses 20 rounds.  In any case the
   number of rounds must be even.  */
#define SALSA20_ROUNDS       20


typedef struct
{
  /* Indices 1-4 and 11-14 holds the key (two identical copies for the
     shorter key size), indices 0, 5, 10, 15 are constant, indices 6, 7
     are the IV, and indices 8, 9 are the block counter:

     C K K K
     K C I I
     B B C K
     K K K C
  */
  u32 input[SALSA20_INPUT_LENGTH];
  u32 pad[SALSA20_INPUT_LENGTH];
  unsigned int unused; /* bytes in the pad.  */
} SALSA20_context_t;


/* The masking of the right shift is needed to allow n == 0 (using
   just 32 - n and 64 - n results in undefined behaviour). Most uses
   of these macros use a constant and non-zero rotation count. */
#define ROTL32(n,x) (((x)<<(n)) | ((x)>>((-(n)&31))))


#ifdef WORDS_BIGENDIAN
# define LE_SWAP32(v)              \
  ( (ROTL32( 8, v) & 0x00FF00FFul) \
   |(ROTL32(24, v) & 0xFF00FF00ul))
#else
# define LE_SWAP32(v) (v)
#endif

#define LE_READ_UINT32(p)                 \
  (  (((u32)(p)[3]) << 24)                \
   | (((u32)(p)[2]) << 16)                \
   | (((u32)(p)[1]) << 8)                 \
   |  ((u32)(p)[0]))


static void salsa20_setiv (void *context, const byte *iv, unsigned int ivlen);
static const char *selftest (void);



#if 0
# define SALSA20_CORE_DEBUG(i) do {		\
    unsigned debug_j;				\
    for (debug_j = 0; debug_j < 16; debug_j++)	\
      {						\
	if (debug_j == 0)			\
	  fprintf(stderr, "%2d:", (i));		\
	else if (debug_j % 4 == 0)		\
	  fprintf(stderr, "\n   ");		\
	fprintf(stderr, " %8x", pad[debug_j]);	\
      }						\
    fprintf(stderr, "\n");			\
  } while (0)
#else
# define SALSA20_CORE_DEBUG(i)
#endif

#define QROUND(x0, x1, x2, x3)      \
  do {                              \
    x1 ^= ROTL32 ( 7, x0 + x3);	    \
    x2 ^= ROTL32 ( 9, x1 + x0);	    \
    x3 ^= ROTL32 (13, x2 + x1);	    \
    x0 ^= ROTL32 (18, x3 + x2);	    \
  } while(0)

static void
salsa20_core (u32 *dst, const u32 *src)
{
  u32 pad[SALSA20_INPUT_LENGTH];
  unsigned int i;

  memcpy (pad, src, sizeof(pad));
  for (i = 0; i < SALSA20_ROUNDS; i += 2)
    {
      SALSA20_CORE_DEBUG (i);
      QROUND (pad[0],  pad[4],  pad[8],  pad[12]);
      QROUND (pad[5],  pad[9],  pad[13], pad[1] );
      QROUND (pad[10], pad[14], pad[2],  pad[6] );
      QROUND (pad[15], pad[3],  pad[7],  pad[11]);

      SALSA20_CORE_DEBUG (i+1);
      QROUND (pad[0],  pad[1],  pad[2],  pad[3] );
      QROUND (pad[5],  pad[6],  pad[7],  pad[4] );
      QROUND (pad[10], pad[11], pad[8],  pad[9] );
      QROUND (pad[15], pad[12], pad[13], pad[14]);
    }
  SALSA20_CORE_DEBUG (i);

  for (i = 0; i < SALSA20_INPUT_LENGTH; i++)
    {
      u32 t = pad[i] + src[i];
      dst[i] = LE_SWAP32 (t);
    }
}
#undef QROUND
#undef SALSA20_CORE_DEBUG

static gcry_err_code_t
salsa20_do_setkey (SALSA20_context_t *ctx,
                   const byte *key, unsigned int keylen)
{
  static int initialized;
  static const char *selftest_failed;

  if (!initialized )
    {
      initialized = 1;
      selftest_failed = selftest ();
      if (selftest_failed)
        log_error ("SALSA20 selftest failed (%s)\n", selftest_failed );
    }
  if (selftest_failed)
    return GPG_ERR_SELFTEST_FAILED;

  if (keylen != SALSA20_MIN_KEY_SIZE
      && keylen != SALSA20_MAX_KEY_SIZE)
    return GPG_ERR_INV_KEYLEN;

  /* These constants are the little endian encoding of the string
     "expand 32-byte k".  For the 128 bit variant, the "32" in that
     string will be fixed up to "16".  */
  ctx->input[0]  = 0x61707865; /* "apxe"  */
  ctx->input[5]  = 0x3320646e; /* "3 dn"  */
  ctx->input[10] = 0x79622d32; /* "yb-2"  */
  ctx->input[15] = 0x6b206574; /* "k et"  */

  ctx->input[1] = LE_READ_UINT32(key + 0);
  ctx->input[2] = LE_READ_UINT32(key + 4);
  ctx->input[3] = LE_READ_UINT32(key + 8);
  ctx->input[4] = LE_READ_UINT32(key + 12);
  if (keylen == SALSA20_MAX_KEY_SIZE) /* 256 bits */
    {
      ctx->input[11] = LE_READ_UINT32(key + 16);
      ctx->input[12] = LE_READ_UINT32(key + 20);
      ctx->input[13] = LE_READ_UINT32(key + 24);
      ctx->input[14] = LE_READ_UINT32(key + 28);
    }
  else  /* 128 bits */
    {
      ctx->input[11] = ctx->input[1];
      ctx->input[12] = ctx->input[2];
      ctx->input[13] = ctx->input[3];
      ctx->input[14] = ctx->input[4];

      ctx->input[5]  -= 0x02000000; /* Change to "1 dn".  */
      ctx->input[10] += 0x00000004; /* Change to "yb-6".  */
    }

  /* We default to a zero nonce.  */
  salsa20_setiv (ctx, NULL, 0);

  return 0;
}


static gcry_err_code_t
salsa20_setkey (void *context, const byte *key, unsigned int keylen)
{
  SALSA20_context_t *ctx = (SALSA20_context_t *)context;
  gcry_err_code_t rc = salsa20_do_setkey (ctx, key, keylen);
  _gcry_burn_stack (300/* FIXME*/);
  return rc;
}


static void
salsa20_setiv (void *context, const byte *iv, unsigned int ivlen)
{
  SALSA20_context_t *ctx = (SALSA20_context_t *)context;

  if (!iv)
    {
      ctx->input[6] = 0;
      ctx->input[7] = 0;
    }
  else if (ivlen == SALSA20_IV_SIZE)
    {
      ctx->input[6] = LE_READ_UINT32(iv + 0);
      ctx->input[7] = LE_READ_UINT32(iv + 4);
    }
  else
    {
      log_info ("WARNING: salsa20_setiv: bad ivlen=%u\n", ivlen);
      ctx->input[6] = 0;
      ctx->input[7] = 0;
    }
  /* Reset the block counter.  */
  ctx->input[8] = 0;
  ctx->input[9] = 0;
  /* Reset the unused pad bytes counter.  */
  ctx->unused = 0;
}



/* Note: This function requires LENGTH > 0.  */
static void
salsa20_do_encrypt_stream (SALSA20_context_t *ctx,
                           byte *outbuf, const byte *inbuf,
                           unsigned int length)
{
  if (ctx->unused)
    {
      unsigned char *p = (void*)ctx->pad;
      unsigned int n;

      gcry_assert (ctx->unused < SALSA20_BLOCK_SIZE);

      n = ctx->unused;
      if (n > length)
        n = length;
      buf_xor (outbuf, inbuf, p + SALSA20_BLOCK_SIZE - ctx->unused, n);
      length -= n;
      outbuf += n;
      inbuf  += n;
      ctx->unused -= n;
      if (!length)
        return;
      gcry_assert (!ctx->unused);
    }

  for (;;)
    {
      /* Create the next pad and bump the block counter.  Note that it
         is the user's duty to change to another nonce not later than
         after 2^70 processed bytes.  */
      salsa20_core (ctx->pad, ctx->input);
      if (!++ctx->input[8])
        ctx->input[9]++;

      if (length <= SALSA20_BLOCK_SIZE)
	{
	  buf_xor (outbuf, inbuf, ctx->pad, length);
          ctx->unused = SALSA20_BLOCK_SIZE - length;
	  return;
	}
      buf_xor (outbuf, inbuf, ctx->pad, SALSA20_BLOCK_SIZE);
      length -= SALSA20_BLOCK_SIZE;
      outbuf += SALSA20_BLOCK_SIZE;
      inbuf  += SALSA20_BLOCK_SIZE;
  }
}


static void
salsa20_encrypt_stream (void *context,
                        byte *outbuf, const byte *inbuf, unsigned int length)
{
  SALSA20_context_t *ctx = (SALSA20_context_t *)context;

  if (length)
    {
      salsa20_do_encrypt_stream (ctx, outbuf, inbuf, length);
      _gcry_burn_stack (/* salsa20_do_encrypt_stream: */
                        2*sizeof (void*)
                        + 3*sizeof (void*) + sizeof (unsigned int)
                        /* salsa20_core: */
                        + 2*sizeof (void*)
                        + 2*sizeof (void*)
                        + 64
                        + sizeof (unsigned int)
                        + sizeof (u32)
                        );
    }
}



static const char*
selftest (void)
{
  SALSA20_context_t ctx;
  byte scratch[8+1];

  static byte key_1[] =
    { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static const byte nonce_1[] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static const byte plaintext_1[] =
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  static const byte ciphertext_1[] =
    { 0xE3, 0xBE, 0x8F, 0xDD, 0x8B, 0xEC, 0xA2, 0xE3};

  salsa20_setkey (&ctx, key_1, sizeof key_1);
  salsa20_setiv  (&ctx, nonce_1, sizeof nonce_1);
  scratch[8] = 0;
  salsa20_encrypt_stream (&ctx, scratch, plaintext_1, sizeof plaintext_1);
  if (memcmp (scratch, ciphertext_1, sizeof ciphertext_1))
    return "Salsa20 encryption test 1 failed.";
  if (scratch[8])
    return "Salsa20 wrote too much.";
  salsa20_setkey( &ctx, key_1, sizeof(key_1));
  salsa20_setiv  (&ctx, nonce_1, sizeof nonce_1);
  salsa20_encrypt_stream (&ctx, scratch, scratch, sizeof plaintext_1);
  if (memcmp (scratch, plaintext_1, sizeof plaintext_1))
    return "Salsa20 decryption test 1 failed.";
  return NULL;
}


gcry_cipher_spec_t _gcry_cipher_spec_salsa20 =
  {
    "SALSA20",  /* name */
    NULL,       /* aliases */
    NULL,       /* oids */
    1,          /* blocksize in bytes. */
    SALSA20_MAX_KEY_SIZE*8,  /* standard key length in bits. */
    sizeof (SALSA20_context_t),
    salsa20_setkey,
    NULL,
    NULL,
    salsa20_encrypt_stream,
    salsa20_encrypt_stream
  };

cipher_extra_spec_t _gcry_cipher_extraspec_salsa20 =
  {
    NULL,
    NULL,
    salsa20_setiv
  };
