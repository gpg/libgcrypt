/* ARMv8 Crypto Extension AES for Libgcrypt
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
 *
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


#ifdef USE_ARM_CE


typedef struct u128_s { u32 a, b, c, d; } u128_t;

extern u32 _gcry_aes_sbox4_armv8_ce(u32 in4b);
extern void _gcry_aes_invmixcol_armv8_ce(u128_t *dst, const u128_t *src);

extern unsigned int _gcry_aes_enc_armv8_ce(const void *keysched, byte *dst,
                                           const byte *src,
                                           unsigned int nrounds);
extern unsigned int _gcry_aes_dec_armv8_ce(const void *keysched, byte *dst,
                                           const byte *src,
                                           unsigned int nrounds);

extern void _gcry_aes_cbc_enc_armv8_ce (const void *keysched,
                                        unsigned char *outbuf,
                                        const unsigned char *inbuf,
                                        unsigned char *iv, size_t nblocks,
                                        int cbc_mac, unsigned int nrounds);
extern void _gcry_aes_cbc_dec_armv8_ce (const void *keysched,
                                        unsigned char *outbuf,
                                        const unsigned char *inbuf,
                                        unsigned char *iv, size_t nblocks,
                                        unsigned int nrounds);

extern void _gcry_aes_cfb_enc_armv8_ce (const void *keysched,
                                        unsigned char *outbuf,
                                        const unsigned char *inbuf,
                                        unsigned char *iv, size_t nblocks,
                                        unsigned int nrounds);
extern void _gcry_aes_cfb_dec_armv8_ce (const void *keysched,
                                        unsigned char *outbuf,
                                        const unsigned char *inbuf,
                                        unsigned char *iv, size_t nblocks,
                                        unsigned int nrounds);

extern void _gcry_aes_ctr_enc_armv8_ce (const void *keysched,
                                        unsigned char *outbuf,
                                        const unsigned char *inbuf,
                                        unsigned char *iv, size_t nblocks,
                                        unsigned int nrounds);

extern void _gcry_aes_ocb_enc_armv8_ce (const void *keysched,
                                        unsigned char *outbuf,
                                        const unsigned char *inbuf,
                                        unsigned char *offset,
                                        unsigned char *checksum,
                                        void **Ls,
                                        size_t nblocks,
                                        unsigned int nrounds);
extern void _gcry_aes_ocb_dec_armv8_ce (const void *keysched,
                                        unsigned char *outbuf,
                                        const unsigned char *inbuf,
                                        unsigned char *offset,
                                        unsigned char *checksum,
                                        void **Ls,
                                        size_t nblocks,
                                        unsigned int nrounds);
extern void _gcry_aes_ocb_auth_armv8_ce (const void *keysched,
                                         const unsigned char *abuf,
                                         unsigned char *offset,
                                         unsigned char *checksum,
                                         void **Ls,
                                         size_t nblocks,
                                         unsigned int nrounds);

typedef void (*ocb_crypt_fn_t) (const void *keysched, unsigned char *outbuf,
                                const unsigned char *inbuf,
                                unsigned char *offset, unsigned char *checksum,
                                void **Ls, size_t nblocks,
                                unsigned int nrounds);

void
_gcry_aes_armv8_ce_setkey (RIJNDAEL_context *ctx, const byte *key)
{
  union
    {
      PROPERLY_ALIGNED_TYPE dummy;
      byte data[MAXKC][4];
      u32 data32[MAXKC];
    } tkk[2];
  unsigned int rounds = ctx->rounds;
  int KC = rounds - 6;
  unsigned int keylen = KC * 4;
  unsigned int i, r, t;
  byte rcon = 1;
  int j;
#define k      tkk[0].data
#define k_u32  tkk[0].data32
#define tk     tkk[1].data
#define tk_u32 tkk[1].data32
#define W      (ctx->keyschenc)
#define W_u32  (ctx->keyschenc32)

  for (i = 0; i < keylen; i++)
    {
      k[i >> 2][i & 3] = key[i];
    }

  for (j = KC-1; j >= 0; j--)
    {
      tk_u32[j] = k_u32[j];
    }
  r = 0;
  t = 0;
  /* Copy values into round key array.  */
  for (j = 0; (j < KC) && (r < rounds + 1); )
    {
      for (; (j < KC) && (t < 4); j++, t++)
        {
          W_u32[r][t] = le_bswap32(tk_u32[j]);
        }
      if (t == 4)
        {
          r++;
          t = 0;
        }
    }

  while (r < rounds + 1)
    {
      tk_u32[0] ^= _gcry_aes_sbox4_armv8_ce(rol(tk_u32[KC - 1], 24)) ^ rcon;

      if (KC != 8)
        {
          for (j = 1; j < KC; j++)
            {
              tk_u32[j] ^= tk_u32[j-1];
            }
        }
      else
        {
          for (j = 1; j < KC/2; j++)
            {
              tk_u32[j] ^= tk_u32[j-1];
            }

          tk_u32[KC/2] ^= _gcry_aes_sbox4_armv8_ce(tk_u32[KC/2 - 1]);

          for (j = KC/2 + 1; j < KC; j++)
            {
              tk_u32[j] ^= tk_u32[j-1];
            }
        }

      /* Copy values into round key array.  */
      for (j = 0; (j < KC) && (r < rounds + 1); )
        {
          for (; (j < KC) && (t < 4); j++, t++)
            {
              W_u32[r][t] = le_bswap32(tk_u32[j]);
            }
          if (t == 4)
            {
              r++;
              t = 0;
            }
        }

      rcon = (rcon << 1) ^ ((rcon >> 7) * 0x1b);
    }

#undef W
#undef tk
#undef k
#undef W_u32
#undef tk_u32
#undef k_u32
  wipememory(&tkk, sizeof(tkk));
}

/* Make a decryption key from an encryption key. */
void
_gcry_aes_armv8_ce_prepare_decryption (RIJNDAEL_context *ctx)
{
  u128_t *ekey = (u128_t *)(void *)ctx->keyschenc;
  u128_t *dkey = (u128_t *)(void *)ctx->keyschdec;
  int rounds = ctx->rounds;
  int rr;
  int r;

#define DO_AESIMC() _gcry_aes_invmixcol_armv8_ce(&dkey[r], &ekey[rr])

  dkey[0] = ekey[rounds];
  r = 1;
  rr = rounds-1;
  DO_AESIMC(); r++; rr--; /* round 1 */
  DO_AESIMC(); r++; rr--; /* round 2 */
  DO_AESIMC(); r++; rr--; /* round 3 */
  DO_AESIMC(); r++; rr--; /* round 4 */
  DO_AESIMC(); r++; rr--; /* round 5 */
  DO_AESIMC(); r++; rr--; /* round 6 */
  DO_AESIMC(); r++; rr--; /* round 7 */
  DO_AESIMC(); r++; rr--; /* round 8 */
  DO_AESIMC(); r++; rr--; /* round 9 */
  if (rounds >= 12)
    {
      if (rounds > 12)
        {
          DO_AESIMC(); r++; rr--; /* round 10 */
          DO_AESIMC(); r++; rr--; /* round 11 */
        }

      DO_AESIMC(); r++; rr--; /* round 12 / 10 */
      DO_AESIMC(); r++; rr--; /* round 13 / 11 */
    }

  dkey[r] = ekey[0];

#undef DO_AESIMC
}

unsigned int
_gcry_aes_armv8_ce_encrypt (const RIJNDAEL_context *ctx, unsigned char *dst,
                            const unsigned char *src)
{
  const void *keysched = ctx->keyschenc32;
  unsigned int nrounds = ctx->rounds;

  return _gcry_aes_enc_armv8_ce(keysched, dst, src, nrounds);
}

unsigned int
_gcry_aes_armv8_ce_decrypt (const RIJNDAEL_context *ctx, unsigned char *dst,
                            const unsigned char *src)
{
  const void *keysched = ctx->keyschdec32;
  unsigned int nrounds = ctx->rounds;

  return _gcry_aes_dec_armv8_ce(keysched, dst, src, nrounds);
}

void
_gcry_aes_armv8_ce_cbc_enc (const RIJNDAEL_context *ctx, unsigned char *outbuf,
                            const unsigned char *inbuf, unsigned char *iv,
                            size_t nblocks, int cbc_mac)
{
  const void *keysched = ctx->keyschenc32;
  unsigned int nrounds = ctx->rounds;

  _gcry_aes_cbc_enc_armv8_ce(keysched, outbuf, inbuf, iv, nblocks, cbc_mac,
                             nrounds);
}

void
_gcry_aes_armv8_ce_cbc_dec (RIJNDAEL_context *ctx, unsigned char *outbuf,
                            const unsigned char *inbuf, unsigned char *iv,
                            size_t nblocks)
{
  const void *keysched = ctx->keyschdec32;
  unsigned int nrounds = ctx->rounds;

  _gcry_aes_cbc_dec_armv8_ce(keysched, outbuf, inbuf, iv, nblocks, nrounds);
}

void
_gcry_aes_armv8_ce_cfb_enc (RIJNDAEL_context *ctx, unsigned char *outbuf,
                            const unsigned char *inbuf, unsigned char *iv,
                            size_t nblocks)
{
  const void *keysched = ctx->keyschenc32;
  unsigned int nrounds = ctx->rounds;

  _gcry_aes_cfb_enc_armv8_ce(keysched, outbuf, inbuf, iv, nblocks, nrounds);
}

void
_gcry_aes_armv8_ce_cfb_dec (RIJNDAEL_context *ctx, unsigned char *outbuf,
                            const unsigned char *inbuf, unsigned char *iv,
                            size_t nblocks)
{
  const void *keysched = ctx->keyschenc32;
  unsigned int nrounds = ctx->rounds;

  _gcry_aes_cfb_dec_armv8_ce(keysched, outbuf, inbuf, iv, nblocks, nrounds);
}

void
_gcry_aes_armv8_ce_ctr_enc (RIJNDAEL_context *ctx, unsigned char *outbuf,
                            const unsigned char *inbuf, unsigned char *iv,
                            size_t nblocks)
{
  const void *keysched = ctx->keyschenc32;
  unsigned int nrounds = ctx->rounds;

  _gcry_aes_ctr_enc_armv8_ce(keysched, outbuf, inbuf, iv, nblocks, nrounds);
}

void
_gcry_aes_armv8_ce_ocb_crypt (gcry_cipher_hd_t c, void *outbuf_arg,
                              const void *inbuf_arg, size_t nblocks,
                              int encrypt)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  const void *keysched = encrypt ? ctx->keyschenc32 : ctx->keyschdec32;
  ocb_crypt_fn_t crypt_fn = encrypt ? _gcry_aes_ocb_enc_armv8_ce
                                    : _gcry_aes_ocb_dec_armv8_ce;
  unsigned char *outbuf = outbuf_arg;
  const unsigned char *inbuf = inbuf_arg;
  unsigned int nrounds = ctx->rounds;
  u64 blkn = c->u_mode.ocb.data_nblocks;
  u64 blkn_offs = blkn - blkn % 32;
  unsigned int n = 32 - blkn % 32;
  unsigned char l_tmp[16];
  void *Ls[32];
  void **l;
  size_t i;

  c->u_mode.ocb.data_nblocks = blkn + nblocks;

  if (nblocks >= 32)
    {
      for (i = 0; i < 32; i += 8)
        {
          Ls[(i + 0 + n) % 32] = (void *)c->u_mode.ocb.L[0];
          Ls[(i + 1 + n) % 32] = (void *)c->u_mode.ocb.L[1];
          Ls[(i + 2 + n) % 32] = (void *)c->u_mode.ocb.L[0];
          Ls[(i + 3 + n) % 32] = (void *)c->u_mode.ocb.L[2];
          Ls[(i + 4 + n) % 32] = (void *)c->u_mode.ocb.L[0];
          Ls[(i + 5 + n) % 32] = (void *)c->u_mode.ocb.L[1];
          Ls[(i + 6 + n) % 32] = (void *)c->u_mode.ocb.L[0];
        }

      Ls[(7 + n) % 32] = (void *)c->u_mode.ocb.L[3];
      Ls[(15 + n) % 32] = (void *)c->u_mode.ocb.L[4];
      Ls[(23 + n) % 32] = (void *)c->u_mode.ocb.L[3];
      l = &Ls[(31 + n) % 32];

      /* Process data in 32 block chunks. */
      while (nblocks >= 32)
        {
          /* l_tmp will be used only every 65536-th block. */
          blkn_offs += 32;
          *l = (void *)ocb_get_l(c, l_tmp, blkn_offs);

          crypt_fn(keysched, outbuf, inbuf, c->u_iv.iv, c->u_ctr.ctr, Ls, 32,
                    nrounds);

          nblocks -= 32;
          outbuf += 32 * 16;
          inbuf  += 32 * 16;
        }

      if (nblocks && l < &Ls[nblocks])
        {
          *l = (void *)ocb_get_l(c, l_tmp, 32 + blkn_offs);
        }
    }
  else
    {
      for (i = 0; i < nblocks; i++)
        Ls[i] = (void *)ocb_get_l(c, l_tmp, ++blkn);
    }

  if (nblocks)
    {
      crypt_fn(keysched, outbuf, inbuf, c->u_iv.iv, c->u_ctr.ctr, Ls, nblocks,
               nrounds);
    }

  wipememory(&l_tmp, sizeof(l_tmp));
}

void
_gcry_aes_armv8_ce_ocb_auth (gcry_cipher_hd_t c, void *abuf_arg,
                             size_t nblocks)
{
  RIJNDAEL_context *ctx = (void *)&c->context.c;
  const void *keysched = ctx->keyschenc32;
  const unsigned char *abuf = abuf_arg;
  unsigned int nrounds = ctx->rounds;
  u64 blkn = c->u_mode.ocb.aad_nblocks;
  u64 blkn_offs = blkn - blkn % 32;
  unsigned int n = 32 - blkn % 32;
  unsigned char l_tmp[16];
  void *Ls[32];
  void **l;
  size_t i;

  c->u_mode.ocb.aad_nblocks = blkn + nblocks;

  if (nblocks >= 32)
    {
      for (i = 0; i < 32; i += 8)
        {
          Ls[(i + 0 + n) % 32] = (void *)c->u_mode.ocb.L[0];
          Ls[(i + 1 + n) % 32] = (void *)c->u_mode.ocb.L[1];
          Ls[(i + 2 + n) % 32] = (void *)c->u_mode.ocb.L[0];
          Ls[(i + 3 + n) % 32] = (void *)c->u_mode.ocb.L[2];
          Ls[(i + 4 + n) % 32] = (void *)c->u_mode.ocb.L[0];
          Ls[(i + 5 + n) % 32] = (void *)c->u_mode.ocb.L[1];
          Ls[(i + 6 + n) % 32] = (void *)c->u_mode.ocb.L[0];
        }

      Ls[(7 + n) % 32] = (void *)c->u_mode.ocb.L[3];
      Ls[(15 + n) % 32] = (void *)c->u_mode.ocb.L[4];
      Ls[(23 + n) % 32] = (void *)c->u_mode.ocb.L[3];
      l = &Ls[(31 + n) % 32];

      /* Process data in 32 block chunks. */
      while (nblocks >= 32)
        {
          /* l_tmp will be used only every 65536-th block. */
          blkn_offs += 32;
          *l = (void *)ocb_get_l(c, l_tmp, blkn_offs);

          _gcry_aes_ocb_auth_armv8_ce(keysched, abuf, c->u_mode.ocb.aad_offset,
                                      c->u_mode.ocb.aad_sum, Ls, 32, nrounds);

          nblocks -= 32;
          abuf += 32 * 16;
        }

      if (nblocks && l < &Ls[nblocks])
        {
          *l = (void *)ocb_get_l(c, l_tmp, 32 + blkn_offs);
        }
    }
  else
    {
      for (i = 0; i < nblocks; i++)
        Ls[i] = (void *)ocb_get_l(c, l_tmp, ++blkn);
    }

  if (nblocks)
    {
      _gcry_aes_ocb_auth_armv8_ce(keysched, abuf, c->u_mode.ocb.aad_offset,
                                  c->u_mode.ocb.aad_sum, Ls, nblocks, nrounds);
    }

  wipememory(&l_tmp, sizeof(l_tmp));
}

#endif /* USE_ARM_CE */
