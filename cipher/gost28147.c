/* gost28147.c - GOST 28147-89 implementation for Libgcrypt
 * Copyright (C) 2012 Free Software Foundation, Inc.
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

/* GOST 28147-89 defines several modes of encryption:
 * - ECB which should be used only for key transfer
 * - CFB mode
 * - OFB-like mode with additional transformation on keystream
 *   RFC 5830 names this 'counter encryption' mode
 *   Original GOST text uses the term 'gammirovanie'
 * - MAC mode
 *
 * This implementation handles ECB and CFB modes via usual libgcrypt handling.
 * OFB-like and MAC modes are unsupported.
 */

#include <config.h>
#include "types.h"
#include "g10lib.h"
#include "cipher.h"


#define max(a, b) (((a) > (b)) ? (a) : (b))


/* This is an s-box from RFC4357, named GostR3411-94-TestParamSet
 * For now it is the only s-box supported, as libgcrypt lacks mechanism
 * for passing parameters to cipher in a usefull way. */
unsigned char test_sbox[16 * 8] = {
  0x4, 0xE, 0x5, 0x7, 0x6, 0x4, 0xD, 0x1,
  0xA, 0xB, 0x8, 0xD, 0xC, 0xB, 0xB, 0xF,
  0x9, 0x4, 0x1, 0xA, 0x7, 0xA, 0x4, 0xD,
  0x2, 0xC, 0xD, 0x1, 0x1, 0x0, 0x1, 0x0,

  0xD, 0x6, 0xA, 0x0, 0x5, 0x7, 0x3, 0x5,
  0x8, 0xD, 0x3, 0x8, 0xF, 0x2, 0xF, 0x7,
  0x0, 0xF, 0x4, 0x9, 0xD, 0x1, 0x5, 0xA,
  0xE, 0xA, 0x2, 0xF, 0x8, 0xD, 0x9, 0x4,

  0x6, 0x2, 0xE, 0xE, 0x4, 0x3, 0x0, 0x9,
  0xB, 0x3, 0xF, 0x4, 0xA, 0x6, 0xA, 0x2,
  0x1, 0x8, 0xC, 0x6, 0x9, 0x8, 0xE, 0x3,
  0xC, 0x1, 0x7, 0xC, 0xE, 0x5, 0x7, 0xE,

  0x7, 0x0, 0x6, 0xB, 0x0, 0x9, 0x6, 0x6,
  0xF, 0x7, 0x0, 0x2, 0x3, 0xC, 0x8, 0xB,
  0x5, 0x5, 0x9, 0x5, 0xB, 0xF, 0x2, 0x8,
  0x3, 0x9, 0xB, 0x3, 0x2, 0xE, 0xC, 0xC,
};

#include "gost.h"

static gcry_err_code_t
gost_setkey (void *c, const byte *key, unsigned keylen)
{
  int i;
  GOST28147_context *ctx = c;

  if (keylen != 256 / 8)
    return GPG_ERR_INV_KEYLEN;

  for (i = 0; i < 8; i++)
    {
      ctx->key[i] = (key[4 * i + 3] << 24) |
                    (key[4 * i + 2] << 16) |
                    (key[4 * i + 1] <<  8) |
                    (key[4 * i + 0] <<  0);
    }
  return GPG_ERR_NO_ERROR;
}

static void
gost_set_subst (GOST28147_context *ctx, unsigned char *sbox)
{
  unsigned i, j;
  for (i = 0; i < 4; i++)
    {
       for (j = 0; j < 256; j++)
         {
           ctx->subst[i][j] = sbox[ (j & 0xf) * 8 + 2 * i + 0] |
                             (sbox[ (j >> 4)  * 8 + 2 * i + 1] << 4);
         }
    }
  ctx->subst_set = 1;
}

static u32
gost_val (GOST28147_context *ctx, u32 cm1, int subkey)
{
  cm1 += ctx->key[subkey];
  cm1 = (ctx->subst[0][ (cm1 >>  0) & 0xff] <<  0) |
        (ctx->subst[1][ (cm1 >>  8) & 0xff] <<  8) |
        (ctx->subst[2][ (cm1 >> 16) & 0xff] << 16) |
        (ctx->subst[3][ (cm1 >> 24) & 0xff] << 24);
  return (cm1 << 11) | (cm1 >> 21);
}

static unsigned int
gost_encrypt_block (void *c, byte *outbuf, const byte *inbuf)
{
  GOST28147_context *ctx = c;
  u32 n1, n2;

  if (!ctx->subst_set)
    gost_set_subst (ctx, test_sbox);

  n1 =  (inbuf[0] << 0) |
        (inbuf[1] << 8) |
        (inbuf[2] << 16) |
        (inbuf[3] << 24);
  n2 =  (inbuf[4] << 0) |
        (inbuf[5] << 8) |
        (inbuf[6] << 16) |
        (inbuf[7] << 24);

  n2 ^= gost_val (ctx, n1, 0); n1 ^= gost_val (ctx, n2, 1);
  n2 ^= gost_val (ctx, n1, 2); n1 ^= gost_val (ctx, n2, 3);
  n2 ^= gost_val (ctx, n1, 4); n1 ^= gost_val (ctx, n2, 5);
  n2 ^= gost_val (ctx, n1, 6); n1 ^= gost_val (ctx, n2, 7);

  n2 ^= gost_val (ctx, n1, 0); n1 ^= gost_val (ctx, n2, 1);
  n2 ^= gost_val (ctx, n1, 2); n1 ^= gost_val (ctx, n2, 3);
  n2 ^= gost_val (ctx, n1, 4); n1 ^= gost_val (ctx, n2, 5);
  n2 ^= gost_val (ctx, n1, 6); n1 ^= gost_val (ctx, n2, 7);

  n2 ^= gost_val (ctx, n1, 0); n1 ^= gost_val (ctx, n2, 1);
  n2 ^= gost_val (ctx, n1, 2); n1 ^= gost_val (ctx, n2, 3);
  n2 ^= gost_val (ctx, n1, 4); n1 ^= gost_val (ctx, n2, 5);
  n2 ^= gost_val (ctx, n1, 6); n1 ^= gost_val (ctx, n2, 7);

  n2 ^= gost_val (ctx, n1, 7); n1 ^= gost_val (ctx, n2, 6);
  n2 ^= gost_val (ctx, n1, 5); n1 ^= gost_val (ctx, n2, 4);
  n2 ^= gost_val (ctx, n1, 3); n1 ^= gost_val (ctx, n2, 2);
  n2 ^= gost_val (ctx, n1, 1); n1 ^= gost_val (ctx, n2, 0);

  outbuf[0 + 0] = (n2 >> (0 * 8)) & 0xff;
  outbuf[1 + 0] = (n2 >> (1 * 8)) & 0xff;
  outbuf[2 + 0] = (n2 >> (2 * 8)) & 0xff;
  outbuf[3 + 0] = (n2 >> (3 * 8)) & 0xff;
  outbuf[0 + 4] = (n1 >> (0 * 8)) & 0xff;
  outbuf[1 + 4] = (n1 >> (1 * 8)) & 0xff;
  outbuf[2 + 4] = (n1 >> (2 * 8)) & 0xff;
  outbuf[3 + 4] = (n1 >> (3 * 8)) & 0xff;

  return /* burn_stack */ 4*sizeof(void*) /* func call */ +
                          3*sizeof(void*) /* stack */ +
                          max( 4*sizeof(void*) /* gost_val call */,
                               3*sizeof(void*) /* gost_set_subst call */ +
                               2*sizeof(void*) /* gost_set subst stack*/ );
}

unsigned int _gcry_gost_enc_one (GOST28147_context *c, const byte *key,
    byte *out, byte *in)
{
  gost_setkey (c, key, 32);
  return gost_encrypt_block (c, out, in) + 5 * sizeof(void *);
}

static unsigned int
gost_decrypt_block (void *c, byte *outbuf, const byte *inbuf)
{
  GOST28147_context *ctx = c;
  u32 n1, n2;

  if (!ctx->subst_set)
    gost_set_subst (ctx, test_sbox);

  n1 =  (inbuf[0] << 0) |
        (inbuf[1] << 8) |
        (inbuf[2] << 16) |
        (inbuf[3] << 24);
  n2 =  (inbuf[4] << 0) |
        (inbuf[5] << 8) |
        (inbuf[6] << 16) |
        (inbuf[7] << 24);

  n2 ^= gost_val (ctx, n1, 0); n1 ^= gost_val (ctx, n2, 1);
  n2 ^= gost_val (ctx, n1, 2); n1 ^= gost_val (ctx, n2, 3);
  n2 ^= gost_val (ctx, n1, 4); n1 ^= gost_val (ctx, n2, 5);
  n2 ^= gost_val (ctx, n1, 6); n1 ^= gost_val (ctx, n2, 7);

  n2 ^= gost_val (ctx, n1, 7); n1 ^= gost_val (ctx, n2, 6);
  n2 ^= gost_val (ctx, n1, 5); n1 ^= gost_val (ctx, n2, 4);
  n2 ^= gost_val (ctx, n1, 3); n1 ^= gost_val (ctx, n2, 2);
  n2 ^= gost_val (ctx, n1, 1); n1 ^= gost_val (ctx, n2, 0);

  n2 ^= gost_val (ctx, n1, 7); n1 ^= gost_val (ctx, n2, 6);
  n2 ^= gost_val (ctx, n1, 5); n1 ^= gost_val (ctx, n2, 4);
  n2 ^= gost_val (ctx, n1, 3); n1 ^= gost_val (ctx, n2, 2);
  n2 ^= gost_val (ctx, n1, 1); n1 ^= gost_val (ctx, n2, 0);

  n2 ^= gost_val (ctx, n1, 7); n1 ^= gost_val (ctx, n2, 6);
  n2 ^= gost_val (ctx, n1, 5); n1 ^= gost_val (ctx, n2, 4);
  n2 ^= gost_val (ctx, n1, 3); n1 ^= gost_val (ctx, n2, 2);
  n2 ^= gost_val (ctx, n1, 1); n1 ^= gost_val (ctx, n2, 0);

  outbuf[0 + 0] = (n2 >> (0 * 8)) & 0xff;
  outbuf[1 + 0] = (n2 >> (1 * 8)) & 0xff;
  outbuf[2 + 0] = (n2 >> (2 * 8)) & 0xff;
  outbuf[3 + 0] = (n2 >> (3 * 8)) & 0xff;
  outbuf[0 + 4] = (n1 >> (0 * 8)) & 0xff;
  outbuf[1 + 4] = (n1 >> (1 * 8)) & 0xff;
  outbuf[2 + 4] = (n1 >> (2 * 8)) & 0xff;
  outbuf[3 + 4] = (n1 >> (3 * 8)) & 0xff;

  return /* burn_stack */ 4*sizeof(void*) /* func call */ +
                          3*sizeof(void*) /* stack */ +
                          max( 4*sizeof(void*) /* gost_val call */,
                               3*sizeof(void*) /* gost_set_subst call */ +
                               2*sizeof(void*) /* gost_set subst stack*/ );
}

gcry_cipher_spec_t _gcry_cipher_spec_gost28147 =
  {
    GCRY_CIPHER_GOST28147, {0, 0},
    "GOST28147", NULL, NULL, 8, 256,
    sizeof (GOST28147_context),
    gost_setkey,
    gost_encrypt_block,
    gost_decrypt_block,
  };
