/* cipher-gcm.c  - Generic Galois Counter Mode implementation
 * Copyright (C) 2013 Dmitry Eremin-Solenikov
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
#include "ath.h"
#include "bufhelp.h"
#include "./cipher-internal.h"

#ifdef GCM_USE_TABLES
static const byte gcmR[256][2] = {
  {0x00, 0x00,}, {0x01, 0xc2,}, {0x03, 0x84,}, {0x02, 0x46,},
  {0x07, 0x08,}, {0x06, 0xca,}, {0x04, 0x8c,}, {0x05, 0x4e,},
  {0x0e, 0x10,}, {0x0f, 0xd2,}, {0x0d, 0x94,}, {0x0c, 0x56,},
  {0x09, 0x18,}, {0x08, 0xda,}, {0x0a, 0x9c,}, {0x0b, 0x5e,},
  {0x1c, 0x20,}, {0x1d, 0xe2,}, {0x1f, 0xa4,}, {0x1e, 0x66,},
  {0x1b, 0x28,}, {0x1a, 0xea,}, {0x18, 0xac,}, {0x19, 0x6e,},
  {0x12, 0x30,}, {0x13, 0xf2,}, {0x11, 0xb4,}, {0x10, 0x76,},
  {0x15, 0x38,}, {0x14, 0xfa,}, {0x16, 0xbc,}, {0x17, 0x7e,},
  {0x38, 0x40,}, {0x39, 0x82,}, {0x3b, 0xc4,}, {0x3a, 0x06,},
  {0x3f, 0x48,}, {0x3e, 0x8a,}, {0x3c, 0xcc,}, {0x3d, 0x0e,},
  {0x36, 0x50,}, {0x37, 0x92,}, {0x35, 0xd4,}, {0x34, 0x16,},
  {0x31, 0x58,}, {0x30, 0x9a,}, {0x32, 0xdc,}, {0x33, 0x1e,},
  {0x24, 0x60,}, {0x25, 0xa2,}, {0x27, 0xe4,}, {0x26, 0x26,},
  {0x23, 0x68,}, {0x22, 0xaa,}, {0x20, 0xec,}, {0x21, 0x2e,},
  {0x2a, 0x70,}, {0x2b, 0xb2,}, {0x29, 0xf4,}, {0x28, 0x36,},
  {0x2d, 0x78,}, {0x2c, 0xba,}, {0x2e, 0xfc,}, {0x2f, 0x3e,},
  {0x70, 0x80,}, {0x71, 0x42,}, {0x73, 0x04,}, {0x72, 0xc6,},
  {0x77, 0x88,}, {0x76, 0x4a,}, {0x74, 0x0c,}, {0x75, 0xce,},
  {0x7e, 0x90,}, {0x7f, 0x52,}, {0x7d, 0x14,}, {0x7c, 0xd6,},
  {0x79, 0x98,}, {0x78, 0x5a,}, {0x7a, 0x1c,}, {0x7b, 0xde,},
  {0x6c, 0xa0,}, {0x6d, 0x62,}, {0x6f, 0x24,}, {0x6e, 0xe6,},
  {0x6b, 0xa8,}, {0x6a, 0x6a,}, {0x68, 0x2c,}, {0x69, 0xee,},
  {0x62, 0xb0,}, {0x63, 0x72,}, {0x61, 0x34,}, {0x60, 0xf6,},
  {0x65, 0xb8,}, {0x64, 0x7a,}, {0x66, 0x3c,}, {0x67, 0xfe,},
  {0x48, 0xc0,}, {0x49, 0x02,}, {0x4b, 0x44,}, {0x4a, 0x86,},
  {0x4f, 0xc8,}, {0x4e, 0x0a,}, {0x4c, 0x4c,}, {0x4d, 0x8e,},
  {0x46, 0xd0,}, {0x47, 0x12,}, {0x45, 0x54,}, {0x44, 0x96,},
  {0x41, 0xd8,}, {0x40, 0x1a,}, {0x42, 0x5c,}, {0x43, 0x9e,},
  {0x54, 0xe0,}, {0x55, 0x22,}, {0x57, 0x64,}, {0x56, 0xa6,},
  {0x53, 0xe8,}, {0x52, 0x2a,}, {0x50, 0x6c,}, {0x51, 0xae,},
  {0x5a, 0xf0,}, {0x5b, 0x32,}, {0x59, 0x74,}, {0x58, 0xb6,},
  {0x5d, 0xf8,}, {0x5c, 0x3a,}, {0x5e, 0x7c,}, {0x5f, 0xbe,},
  {0xe1, 0x00,}, {0xe0, 0xc2,}, {0xe2, 0x84,}, {0xe3, 0x46,},
  {0xe6, 0x08,}, {0xe7, 0xca,}, {0xe5, 0x8c,}, {0xe4, 0x4e,},
  {0xef, 0x10,}, {0xee, 0xd2,}, {0xec, 0x94,}, {0xed, 0x56,},
  {0xe8, 0x18,}, {0xe9, 0xda,}, {0xeb, 0x9c,}, {0xea, 0x5e,},
  {0xfd, 0x20,}, {0xfc, 0xe2,}, {0xfe, 0xa4,}, {0xff, 0x66,},
  {0xfa, 0x28,}, {0xfb, 0xea,}, {0xf9, 0xac,}, {0xf8, 0x6e,},
  {0xf3, 0x30,}, {0xf2, 0xf2,}, {0xf0, 0xb4,}, {0xf1, 0x76,},
  {0xf4, 0x38,}, {0xf5, 0xfa,}, {0xf7, 0xbc,}, {0xf6, 0x7e,},
  {0xd9, 0x40,}, {0xd8, 0x82,}, {0xda, 0xc4,}, {0xdb, 0x06,},
  {0xde, 0x48,}, {0xdf, 0x8a,}, {0xdd, 0xcc,}, {0xdc, 0x0e,},
  {0xd7, 0x50,}, {0xd6, 0x92,}, {0xd4, 0xd4,}, {0xd5, 0x16,},
  {0xd0, 0x58,}, {0xd1, 0x9a,}, {0xd3, 0xdc,}, {0xd2, 0x1e,},
  {0xc5, 0x60,}, {0xc4, 0xa2,}, {0xc6, 0xe4,}, {0xc7, 0x26,},
  {0xc2, 0x68,}, {0xc3, 0xaa,}, {0xc1, 0xec,}, {0xc0, 0x2e,},
  {0xcb, 0x70,}, {0xca, 0xb2,}, {0xc8, 0xf4,}, {0xc9, 0x36,},
  {0xcc, 0x78,}, {0xcd, 0xba,}, {0xcf, 0xfc,}, {0xce, 0x3e,},
  {0x91, 0x80,}, {0x90, 0x42,}, {0x92, 0x04,}, {0x93, 0xc6,},
  {0x96, 0x88,}, {0x97, 0x4a,}, {0x95, 0x0c,}, {0x94, 0xce,},
  {0x9f, 0x90,}, {0x9e, 0x52,}, {0x9c, 0x14,}, {0x9d, 0xd6,},
  {0x98, 0x98,}, {0x99, 0x5a,}, {0x9b, 0x1c,}, {0x9a, 0xde,},
  {0x8d, 0xa0,}, {0x8c, 0x62,}, {0x8e, 0x24,}, {0x8f, 0xe6,},
  {0x8a, 0xa8,}, {0x8b, 0x6a,}, {0x89, 0x2c,}, {0x88, 0xee,},
  {0x83, 0xb0,}, {0x82, 0x72,}, {0x80, 0x34,}, {0x81, 0xf6,},
  {0x84, 0xb8,}, {0x85, 0x7a,}, {0x87, 0x3c,}, {0x86, 0xfe,},
  {0xa9, 0xc0,}, {0xa8, 0x02,}, {0xaa, 0x44,}, {0xab, 0x86,},
  {0xae, 0xc8,}, {0xaf, 0x0a,}, {0xad, 0x4c,}, {0xac, 0x8e,},
  {0xa7, 0xd0,}, {0xa6, 0x12,}, {0xa4, 0x54,}, {0xa5, 0x96,},
  {0xa0, 0xd8,}, {0xa1, 0x1a,}, {0xa3, 0x5c,}, {0xa2, 0x9e,},
  {0xb5, 0xe0,}, {0xb4, 0x22,}, {0xb6, 0x64,}, {0xb7, 0xa6,},
  {0xb2, 0xe8,}, {0xb3, 0x2a,}, {0xb1, 0x6c,}, {0xb0, 0xae,},
  {0xbb, 0xf0,}, {0xba, 0x32,}, {0xb8, 0x74,}, {0xb9, 0xb6,},
  {0xbc, 0xf8,}, {0xbd, 0x3a,}, {0xbf, 0x7c,}, {0xbe, 0xbe,},
};

static unsigned
bshift (unsigned char *b)
{
  unsigned char c;
  int i;
  c = b[15] & 1;
  for (i = 15; i > 0; i--)
    {
      b[i] = (b[i] >> 1) | (b[i - 1] << 7);
    }
  b[i] >>= 1;
  return c;
}

static void
fillM (unsigned char *h, unsigned char *M)
{
  int i, j;
  memset (&M[0 * 16], 0, 16);
  memcpy (&M[8 * 16], h, 16);
  for (i = 4; i > 0; i /= 2)
    {
      memcpy (&M[i * 16], &M[2 * i * 16], 16);
      if (bshift (&M[i * 16]))
        M[i * 16 + 0] ^= 0xe1;
    }
  for (i = 2; i < 16; i *= 2)
    for (j = 1; j < i; j++)
      buf_xor (&M[(i + j) * 16], &M[i * 16], &M[j * 16], 16);
}

static void
ghash (unsigned char *result, const unsigned char *buf,
       const unsigned char *gcmM)
{
  unsigned char V[16];
  int i;

  buf_xor (V, result, buf, 16);

  memset (result, 0, 16);

  for (i = 15; i >= 0; i--)
    {
      byte A = result[15];
      byte T[16];
      int j;
      const byte *M = &gcmM[(V[i] & 0xf) * 16];

      memmove (result + 1, result, 15);
      result[0] = gcmR[A][0];
      result[1] ^= gcmR[A][1];

      T[0] = M[0] >> 4;
      for (j = 1; j < 16; j++)
        T[j] = (M[j] >> 4) | (M[j - 1] << 4);
      T[0] ^= gcmR[(M[15] & 0xf) << 4][0];
      T[1] ^= gcmR[(M[15] & 0xf) << 4][1];
      buf_xor (T, T, &gcmM[(V[i] >> 4) * 16], 16);
      buf_xor (result, result, T, 16);
    }
}

#define GHASH(c, result, buf) ghash (result, buf, c->gcm_table);

#else

static unsigned long
bshift (unsigned long *b)
{
  unsigned long c;
  int i;
  c = b[3] & 1;
  for (i = 3; i > 0; i--)
    {
      b[i] = (b[i] >> 1) | (b[i - 1] << 31);
    }
  b[i] >>= 1;
  return c;
}

static void
ghash (unsigned char *hsub, unsigned char *result, const unsigned char *buf)
{
  unsigned long V[4];
  int i, j;
  byte *p;

#ifdef WORDS_BIGENDIAN
  p = result;
#else
  unsigned long T[4];

  buf_xor (V, result, buf, 16);
  for (i = 0; i < 4; i++)
    {
      V[i] = (V[i] & 0x00ff00ff) << 8 | (V[i] & 0xff00ff00) >> 8;
      V[i] = (V[i] & 0x0000ffff) << 16 | (V[i] & 0xffff0000) >> 16;
    }
  p = (byte *) T;
#endif

  memset (p, 0, 16);

  for (i = 0; i < 16; i++)
    {
      for (j = 0x80; j; j >>= 1)
        {
          if (hsub[i] & j)
            buf_xor (p, p, V, 16);
          if (bshift (V))
            V[0] ^= 0xe1000000;
        }
    }
#ifndef WORDS_BIGENDIAN
  for (i = 0, p = (byte *) T; i < 16; i += 4, p += 4)
    {
      result[i + 0] = p[3];
      result[i + 1] = p[2];
      result[i + 2] = p[1];
      result[i + 3] = p[0];
    }
#endif
}

#define fillM(h, M) do { } while (0)

#define GHASH(c, result, buf) ghash (c->u_iv.iv, result, buf);
#endif


gcry_err_code_t
_gcry_cipher_gcm_encrypt (gcry_cipher_hd_t c,
                          byte * outbuf, unsigned int outbuflen,
                          const byte * inbuf, unsigned int inbuflen)
{
  unsigned int n;
  int i;
  unsigned int blocksize = c->spec->blocksize;
  unsigned char tmp[MAX_BLOCKSIZE];

  if (blocksize >= 0x20)
    return GPG_ERR_CIPHER_ALGO;
  if (blocksize != 0x10)
    return GPG_ERR_CIPHER_ALGO;
  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if (!c->marks.iv)
    {
      memset (tmp, 0, 16);
      _gcry_cipher_gcm_setiv (c, tmp, 16);
    }

  while (inbuflen)
    {
      for (i = blocksize; i > blocksize - 4; i--)
        {
          c->u_ctr.ctr[i - 1]++;
          if (c->u_ctr.ctr[i - 1] != 0)
            break;
        }

      n = blocksize < inbuflen ? blocksize : inbuflen;

      i = blocksize - 1;
      c->length[i] += n * 8;
      for (; c->length[i] == 0 && i > blocksize / 2; i--)
        c->length[i - 1]++;

      c->spec->encrypt (&c->context.c, tmp, c->u_ctr.ctr);
      if (n < blocksize)
        {
          buf_xor_2dst (outbuf, tmp, inbuf, n);
          memset (tmp + n, 0, blocksize - n);
          GHASH (c, c->u_tag.tag, tmp);
        }
      else
        {
          buf_xor (outbuf, tmp, inbuf, n);
          GHASH (c, c->u_tag.tag, outbuf);
        }

      inbuflen -= n;
      outbuf += n;
      inbuf += n;
    }

  return 0;
}

gcry_err_code_t
_gcry_cipher_gcm_decrypt (gcry_cipher_hd_t c,
                          byte * outbuf, unsigned int outbuflen,
                          const byte * inbuf, unsigned int inbuflen)
{
  unsigned int n;
  int i;
  unsigned int blocksize = c->spec->blocksize;
  unsigned char tmp[MAX_BLOCKSIZE];

  if (blocksize >= 0x20)
    return GPG_ERR_CIPHER_ALGO;
  if (blocksize != 0x10)
    return GPG_ERR_CIPHER_ALGO;
  if (outbuflen < inbuflen)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if (!c->marks.iv)
    {
      memset (tmp, 0, 16);
      _gcry_cipher_gcm_setiv (c, tmp, 16);
    }

  while (inbuflen)
    {
      for (i = blocksize; i > blocksize - 4; i--)
        {
          c->u_ctr.ctr[i - 1]++;
          if (c->u_ctr.ctr[i - 1] != 0)
            break;
        }

      n = blocksize < inbuflen ? blocksize : inbuflen;
      if (n < blocksize)
        {
          memcpy (tmp, inbuf, n);
          memset (tmp + n, 0, blocksize - n);
          GHASH (c, c->u_tag.tag, tmp);
        }
      else
        {
          GHASH (c, c->u_tag.tag, inbuf);
        }

      i = blocksize - 1;
      c->length[i] += n * 8;
      for (; c->length[i] == 0 && i > blocksize / 2; i--)
        c->length[i - 1]++;

      c->spec->encrypt (&c->context.c, tmp, c->u_ctr.ctr);

      buf_xor (outbuf, inbuf, tmp, n);

      inbuflen -= n;
      outbuf += n;
      inbuf += n;
    }

  return 0;
}

gcry_err_code_t
_gcry_cipher_gcm_authenticate (gcry_cipher_hd_t c,
                               const byte * aadbuf, unsigned int aadbuflen)
{
  unsigned int n;
  int i;
  unsigned int blocksize = c->spec->blocksize;
  unsigned char tmp[MAX_BLOCKSIZE];

  if (!c->marks.iv)
    {
      memset (tmp, 0, 16);
      _gcry_cipher_gcm_setiv (c, tmp, 16);
    }

  n = aadbuflen;
  i = blocksize / 2;
  c->length[i - 1] = (n % 0x20) * 8;
  n /= 0x20;
  for (; n && i > 0; i--, n >>= 8)
    c->length[i - 1] = n & 0xff;

  while (aadbuflen >= blocksize)
    {
      GHASH (c, c->u_tag.tag, aadbuf);

      aadbuflen -= blocksize;
      aadbuf += blocksize;
    }

  if (aadbuflen != 0)
    {
      memcpy (tmp, aadbuf, aadbuflen);
      memset (tmp + aadbuflen, 0, blocksize - aadbuflen);

      GHASH (c, c->u_tag.tag, tmp);
    }

  return 0;
}

void
_gcry_cipher_gcm_setiv (gcry_cipher_hd_t c,
                        const byte * iv, unsigned int ivlen)
{
  memset (c->length, 0, 16);
  memset (c->u_tag.tag, 0, 16);
  c->spec->encrypt (&c->context.c, c->u_iv.iv, c->u_tag.tag);

  fillM (c->u_iv.iv, c->gcm_table);

  if (ivlen != 16 - 4)
    {
      unsigned char tmp[MAX_BLOCKSIZE];
      unsigned n;
      memset (c->u_ctr.ctr, 0, 16);
      for (n = ivlen; n >= 16; n -= 16, iv += 16)
        GHASH (c, c->u_ctr.ctr, iv);
      if (n != 0)
        {
          memcpy (tmp, iv, n);
          memset (tmp + n, 0, 16 - n);
          GHASH (c, c->u_ctr.ctr, tmp);
        }
      memset (tmp, 0, 16);
      n = 16;
      tmp[n - 1] = (ivlen % 0x20) * 8;
      ivlen /= 0x20;
      n--;
      for (; n > 0; n--, ivlen >>= 8)
        tmp[n - 1] = ivlen & 0xff;
      GHASH (c, c->u_ctr.ctr, tmp);
    }
  else
    {
      memcpy (c->u_ctr.ctr, iv, ivlen);
      c->u_ctr.ctr[12] = c->u_ctr.ctr[13] = c->u_ctr.ctr[14] = 0;
      c->u_ctr.ctr[15] = 1;
    }

  c->spec->encrypt (&c->context.c, c->lastiv, c->u_ctr.ctr);
  c->marks.iv = 1;

}

static gcry_err_code_t
_gcry_cipher_gcm_tag (gcry_cipher_hd_t c,
                      byte * outbuf, unsigned int outbuflen, int check)
{
  if (outbuflen < 16)
    return GPG_ERR_BUFFER_TOO_SHORT;

  if (!c->marks.tag)
    {
      GHASH (c, c->u_tag.tag, c->length);
      buf_xor (c->u_tag.tag, c->lastiv, c->u_tag.tag, 16);
      c->marks.tag = 1;
    }
  memcpy (outbuf, c->u_tag.tag, 16);
  if (!check)
    {
      memcpy (outbuf, c->u_tag.tag, outbuflen);
      return GPG_ERR_NO_ERROR;
    }
  else
    {
      int diff, i;

      /* Constant-time compare. */
      for (i = 0, diff = 0; i < outbuflen; i++)
        diff -= ! !(outbuf[i] - c->u_tag.tag[i]);

      return !diff ? GPG_ERR_NO_ERROR : GPG_ERR_CHECKSUM;
    }

  return 0;
}

gcry_err_code_t
_gcry_cipher_gcm_get_tag (gcry_cipher_hd_t c, unsigned char *outtag,
                          size_t taglen)
{
  return _gcry_cipher_gcm_tag (c, outtag, taglen, 0);
}


gcry_err_code_t
_gcry_cipher_gcm_check_tag (gcry_cipher_hd_t c, const unsigned char *intag,
                            size_t taglen)
{
  return _gcry_cipher_gcm_tag (c, (unsigned char *) intag, taglen, 1);
}
