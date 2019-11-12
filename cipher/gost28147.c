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
#include "bufhelp.h"

#include "gost.h"
#include "gost-sb.h"

static gcry_err_code_t
gost_setkey (void *c, const byte *key, unsigned keylen,
             gcry_cipher_hd_t hd)
{
  int i;
  GOST28147_context *ctx = c;

  (void)hd;

  if (keylen != 256 / 8)
    return GPG_ERR_INV_KEYLEN;

  if (!ctx->sbox)
    ctx->sbox = sbox_test_3411;

  for (i = 0; i < 8; i++)
    {
      ctx->key[i] = buf_get_le32(&key[4*i]);
    }
  return GPG_ERR_NO_ERROR;
}

static u32
gost_val (u32 subkey, u32 cm1, const u32 *sbox)
{
  cm1 += subkey;
  cm1 = sbox[0*256 + ((cm1 >>  0) & 0xff)] |
        sbox[1*256 + ((cm1 >>  8) & 0xff)] |
        sbox[2*256 + ((cm1 >> 16) & 0xff)] |
        sbox[3*256 + ((cm1 >> 24) & 0xff)];
  return cm1;
}

static unsigned int
_gost_encrypt_data (const u32 *sbox, const u32 *key, u32 *o1, u32 *o2, u32 n1, u32 n2)
{
  n2 ^= gost_val (key[0], n1, sbox); n1 ^= gost_val (key[1], n2, sbox);
  n2 ^= gost_val (key[2], n1, sbox); n1 ^= gost_val (key[3], n2, sbox);
  n2 ^= gost_val (key[4], n1, sbox); n1 ^= gost_val (key[5], n2, sbox);
  n2 ^= gost_val (key[6], n1, sbox); n1 ^= gost_val (key[7], n2, sbox);

  n2 ^= gost_val (key[0], n1, sbox); n1 ^= gost_val (key[1], n2, sbox);
  n2 ^= gost_val (key[2], n1, sbox); n1 ^= gost_val (key[3], n2, sbox);
  n2 ^= gost_val (key[4], n1, sbox); n1 ^= gost_val (key[5], n2, sbox);
  n2 ^= gost_val (key[6], n1, sbox); n1 ^= gost_val (key[7], n2, sbox);

  n2 ^= gost_val (key[0], n1, sbox); n1 ^= gost_val (key[1], n2, sbox);
  n2 ^= gost_val (key[2], n1, sbox); n1 ^= gost_val (key[3], n2, sbox);
  n2 ^= gost_val (key[4], n1, sbox); n1 ^= gost_val (key[5], n2, sbox);
  n2 ^= gost_val (key[6], n1, sbox); n1 ^= gost_val (key[7], n2, sbox);

  n2 ^= gost_val (key[7], n1, sbox); n1 ^= gost_val (key[6], n2, sbox);
  n2 ^= gost_val (key[5], n1, sbox); n1 ^= gost_val (key[4], n2, sbox);
  n2 ^= gost_val (key[3], n1, sbox); n1 ^= gost_val (key[2], n2, sbox);
  n2 ^= gost_val (key[1], n1, sbox); n1 ^= gost_val (key[0], n2, sbox);

  *o1 = n2;
  *o2 = n1;

  return /* burn_stack */ 4*sizeof(void*) /* func call */ +
                          3*sizeof(void*) /* stack */ +
                          4*sizeof(void*) /* gost_val call */;
}

static unsigned int
gost_encrypt_block (void *c, byte *outbuf, const byte *inbuf)
{
  GOST28147_context *ctx = c;
  u32 n1, n2;
  unsigned int burn;

  n1 = buf_get_le32 (inbuf);
  n2 = buf_get_le32 (inbuf+4);

  burn = _gost_encrypt_data(ctx->sbox, ctx->key, &n1, &n2, n1, n2);

  buf_put_le32 (outbuf+0, n1);
  buf_put_le32 (outbuf+4, n2);

  return /* burn_stack */ burn + 6*sizeof(void*) /* func call */;
}

unsigned int _gcry_gost_enc_data (GOST28147_context *c, const u32 *key,
    u32 *o1, u32 *o2, u32 n1, u32 n2, int cryptopro)
{
  const u32 *sbox;
  if (cryptopro)
    sbox = sbox_CryptoPro_3411;
  else
    sbox = sbox_test_3411;
  return _gost_encrypt_data (sbox, key, o1, o2, n1, n2) + 7 * sizeof(void *);
}

static unsigned int
gost_decrypt_block (void *c, byte *outbuf, const byte *inbuf)
{
  GOST28147_context *ctx = c;
  u32 n1, n2;
  const u32 *sbox = ctx->sbox;

  n1 = buf_get_le32 (inbuf);
  n2 = buf_get_le32 (inbuf+4);

  n2 ^= gost_val (ctx->key[0], n1, sbox); n1 ^= gost_val (ctx->key[1], n2, sbox);
  n2 ^= gost_val (ctx->key[2], n1, sbox); n1 ^= gost_val (ctx->key[3], n2, sbox);
  n2 ^= gost_val (ctx->key[4], n1, sbox); n1 ^= gost_val (ctx->key[5], n2, sbox);
  n2 ^= gost_val (ctx->key[6], n1, sbox); n1 ^= gost_val (ctx->key[7], n2, sbox);

  n2 ^= gost_val (ctx->key[7], n1, sbox); n1 ^= gost_val (ctx->key[6], n2, sbox);
  n2 ^= gost_val (ctx->key[5], n1, sbox); n1 ^= gost_val (ctx->key[4], n2, sbox);
  n2 ^= gost_val (ctx->key[3], n1, sbox); n1 ^= gost_val (ctx->key[2], n2, sbox);
  n2 ^= gost_val (ctx->key[1], n1, sbox); n1 ^= gost_val (ctx->key[0], n2, sbox);

  n2 ^= gost_val (ctx->key[7], n1, sbox); n1 ^= gost_val (ctx->key[6], n2, sbox);
  n2 ^= gost_val (ctx->key[5], n1, sbox); n1 ^= gost_val (ctx->key[4], n2, sbox);
  n2 ^= gost_val (ctx->key[3], n1, sbox); n1 ^= gost_val (ctx->key[2], n2, sbox);
  n2 ^= gost_val (ctx->key[1], n1, sbox); n1 ^= gost_val (ctx->key[0], n2, sbox);

  n2 ^= gost_val (ctx->key[7], n1, sbox); n1 ^= gost_val (ctx->key[6], n2, sbox);
  n2 ^= gost_val (ctx->key[5], n1, sbox); n1 ^= gost_val (ctx->key[4], n2, sbox);
  n2 ^= gost_val (ctx->key[3], n1, sbox); n1 ^= gost_val (ctx->key[2], n2, sbox);
  n2 ^= gost_val (ctx->key[1], n1, sbox); n1 ^= gost_val (ctx->key[0], n2, sbox);

  buf_put_le32 (outbuf+0, n2);
  buf_put_le32 (outbuf+4, n1);

  return /* burn_stack */ 4*sizeof(void*) /* func call */ +
                          3*sizeof(void*) /* stack */ +
                          4*sizeof(void*) /* gost_val call */;
}

static gpg_err_code_t
gost_set_sbox (GOST28147_context *ctx, const char *oid)
{
  int i;

  for (i = 0; gost_oid_map[i].oid; i++)
    {
      if (!strcmp(gost_oid_map[i].oid, oid))
        {
          ctx->sbox = gost_oid_map[i].sbox;
          return 0;
        }
    }
  return GPG_ERR_VALUE_NOT_FOUND;
}

static gpg_err_code_t
gost_set_extra_info (void *c, int what, const void *buffer, size_t buflen)
{
  GOST28147_context *ctx = c;
  gpg_err_code_t ec = 0;

  (void)buffer;
  (void)buflen;

  switch (what)
    {
    case GCRYCTL_SET_SBOX:
      ec = gost_set_sbox (ctx, buffer);
      break;

    default:
      ec = GPG_ERR_INV_OP;
      break;
    }
  return ec;
}

static gcry_cipher_oid_spec_t oids_gost28147[] =
  {
    /* { "1.2.643.2.2.31.0", GCRY_CIPHER_MODE_CNTGOST }, */
    { "1.2.643.2.2.31.1", GCRY_CIPHER_MODE_CFB },
    { "1.2.643.2.2.31.2", GCRY_CIPHER_MODE_CFB },
    { "1.2.643.2.2.31.3", GCRY_CIPHER_MODE_CFB },
    { "1.2.643.2.2.31.4", GCRY_CIPHER_MODE_CFB },
    { NULL }
  };

gcry_cipher_spec_t _gcry_cipher_spec_gost28147 =
  {
    GCRY_CIPHER_GOST28147, {0, 0},
    "GOST28147", NULL, oids_gost28147, 8, 256,
    sizeof (GOST28147_context),
    gost_setkey,
    gost_encrypt_block,
    gost_decrypt_block,
    NULL, NULL, NULL, gost_set_extra_info,
  };
